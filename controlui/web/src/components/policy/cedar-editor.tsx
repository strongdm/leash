"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Editor from "react-simple-code-editor";
import { AlertTriangle, Clipboard, Download } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { highlightCedar } from "@/lib/policy/cedar-language";
import {
  validateCedarPolicy,
  type LintIssue,
} from "@/lib/policy/api";
import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";

type Props = {
  showHeader?: boolean;
};

const VALIDATION_DEBOUNCE_MS = 500;

export default function CedarEditor({ showHeader = true }: Props) {
  const {
    cedarRuntime,
    cedarFile,
    cedarBaseline,
    submitting,
    submitError,
    persistCedar,
    applyEnforce,
    enforcementMode,
    editorDraft,
    setEditorDraft,
    showNotice: contextShowNotice,
    notice,
  } = usePolicyBlocksContext();

  const [copied, setCopied] = useState(false);
  const [showShortcutTitle, setShowShortcutTitle] = useState(false);
  const shortcutHoverTimerRef = useRef<number | null>(null);
  const [lintIssues, setLintIssues] = useState<LintIssue[]>([]);

  const [confirm, setConfirm] = useState<{
    summary: { allowAllConnect: boolean; allowConnect: number; denyConnect: number };
    issues?: LintIssue[];
    show: boolean;
  } | null>(null);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(timer);
  }, [copied]);

  // Debounced validation
  useEffect(() => {
    if (!editorDraft.trim()) {
      setLintIssues([]);
      return;
    }

    const controller = new AbortController();
    const timeout = window.setTimeout(async () => {
      try {
        const summary = await validateCedarPolicy(editorDraft, controller.signal);
        if (!controller.signal.aborted) {
          setLintIssues(summary.issues ?? []);
        }
      } catch {
        if (!controller.signal.aborted) {
          setLintIssues([]);
        }
      }
    }, VALIDATION_DEBOUNCE_MS);

    return () => {
      controller.abort();
      window.clearTimeout(timeout);
    };
  }, [editorDraft]);

  const scheduleShortcutTitle = () => {
    if (shortcutHoverTimerRef.current !== null) return;
    shortcutHoverTimerRef.current = window.setTimeout(() => {
      setShowShortcutTitle(true);
      shortcutHoverTimerRef.current = null;
    }, 1000);
  };

  const clearShortcutTitle = () => {
    if (shortcutHoverTimerRef.current !== null) {
      window.clearTimeout(shortcutHoverTimerRef.current);
      shortcutHoverTimerRef.current = null;
    }
    if (showShortcutTitle) setShowShortcutTitle(false);
  };

  const onSave = useCallback(async () => {
    const ok = await persistCedar(editorDraft, false);
    if (ok) {
      if (enforcementMode === "enforce") {
        await applyEnforce();
        contextShowNotice("Saved and applied");
      } else {
        contextShowNotice("Saved");
      }
    }
  }, [editorDraft, persistCedar, enforcementMode, applyEnforce, contextShowNotice]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        void onSave();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onSave]);

  const copyEditorContents = useCallback(async () => {
    if (typeof navigator === "undefined" || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(editorDraft);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }, [editorDraft]);

  const onDownloadPolicy = useCallback(async () => {
    const contents = editorDraft.trim() || cedarRuntime.trim() || cedarFile.trim() || cedarBaseline.trim();
    if (!contents || typeof window === "undefined") return;

    const blob = new Blob([contents], { type: "text/plain;charset=utf-8" });
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    anchor.href = url;
    anchor.download = `leash-policy-${timestamp}.cedar`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    window.setTimeout(() => window.URL.revokeObjectURL(url), 0);
  }, [editorDraft, cedarRuntime, cedarFile, cedarBaseline]);

  const startPermissive = useCallback(() => {
    if (!cedarBaseline) return;
    const next = editorDraft.trim() ? `${editorDraft}\n\n${cedarBaseline}` : cedarBaseline;
    setEditorDraft(next);
    contextShowNotice("Inserted permissive baseline");
  }, [cedarBaseline, editorDraft, setEditorDraft, contextShowNotice]);

  const isEditorEmpty = editorDraft.trim().length === 0;
  const lintErrors = lintIssues.filter((i) => i.severity === "error");

  return (
    <section className="space-y-3">
      {showHeader && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-border bg-slate-900/60 px-4 py-2.5">
          <div>
            <label htmlFor="cedar-editor" className="block text-sm font-semibold text-cyan-300 tracking-wide">
              Policy Editor
            </label>
            <p className="text-xs text-muted-foreground">Edit and apply Cedar policy to this running instance.</p>
          </div>
          <TooltipProvider>
            <div className="flex items-center gap-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    size="icon"
                    variant="ghost"
                    aria-label="Copy policy to clipboard"
                    className="h-8 w-8 text-cyan-200 hover:text-cyan-100 hover:bg-cyan-500/10"
                    onClick={copyEditorContents}
                  >
                    <Clipboard className="size-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Copy policy to clipboard</TooltipContent>
              </Tooltip>
              {copied && <span className="text-xs text-cyan-200">Copied</span>}
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    size="icon"
                    variant="ghost"
                    aria-label="Download policy"
                    className="h-8 w-8 text-cyan-200 hover:text-cyan-100 hover:bg-cyan-500/10"
                    onClick={onDownloadPolicy}
                    disabled={isEditorEmpty && cedarRuntime.trim().length === 0 && cedarFile.trim().length === 0}
                  >
                    <Download className="size-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Download policy</TooltipContent>
              </Tooltip>
              <Button size="sm" variant="outline" className="border-border text-cyan-200 hover:bg-cyan-500/20" onClick={startPermissive}>
                Start Permissive
              </Button>
            </div>
          </TooltipProvider>
        </div>
      )}

      <div className="relative border border-border rounded-md overflow-hidden bg-slate-900/60">
        {isEditorEmpty && (
          <span className="pointer-events-none absolute left-[60px] top-3 text-xs text-slate-400/70 z-10">
            {'permit (principal, action == Action::"NetworkConnect", resource == Host::"api.example.com");'}
          </span>
        )}
        <Editor
          value={editorDraft}
          onValueChange={setEditorDraft}
          highlight={highlightCedar}
          padding={12}
          textareaId="cedar-editor"
          className="cedar-editor-root min-h-[260px] font-mono text-sm leading-relaxed text-cyan-100 caret-cyan-400"
          style={{
            fontFamily: "var(--font-mono, 'JetBrains Mono', 'Fira Code', monospace)",
          }}
        />
      </div>

      {lintErrors.length > 0 && (
        <div className="rounded-md border border-red-500/30 bg-red-950/30 p-2">
          <div className="text-xs font-semibold text-red-300 mb-1">Lint errors ({lintErrors.length})</div>
          <ul className="list-disc ml-4 space-y-0.5">
            {lintErrors.map((issue, idx) => (
              <li key={idx} className="text-[11px] text-red-200/90">
                <span className="font-mono text-red-300">{issue.code}</span>: {issue.message}
                {issue.suggestion && <span className="text-slate-300/80"> — {issue.suggestion}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex items-center justify-between gap-3">
        {submitError && (
          <span className="text-sm font-medium text-red-400">
            {submitError.startsWith("Error:") ? submitError : `Error: ${submitError}`}
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          <Button
            size="sm"
            onClick={async () => {
              try {
                const summary = await validateCedarPolicy(editorDraft);
                const errors = (summary.issues || []).filter((issue) => issue.severity === "error");
                if (errors.length > 0 || (!summary.allowAllConnect && summary.denyConnect > 0 && summary.allowConnect === 0)) {
                  setConfirm({
                    summary: {
                      allowAllConnect: summary.allowAllConnect,
                      allowConnect: summary.allowConnect,
                      denyConnect: summary.denyConnect,
                    },
                    issues: errors,
                    show: true,
                  });
                  return;
                }
                await onSave();
              } catch {
                setConfirm({ summary: { allowAllConnect: false, allowConnect: 0, denyConnect: 0 }, show: true });
              }
            }}
            disabled={submitting || isEditorEmpty}
            className="border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/20"
            variant="outline"
            title={showShortcutTitle ? "Shortcut: Cmd+S / Ctrl+S" : undefined}
            onMouseEnter={scheduleShortcutTitle}
            onMouseLeave={clearShortcutTitle}
            onFocus={scheduleShortcutTitle}
            onBlur={clearShortcutTitle}
          >
            {submitting ? "Saving..." : "Save"}
          </Button>
        </div>
      </div>

      {confirm?.show && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-full max-w-md rounded-md border border-yellow-500/40 bg-slate-900 text-slate-200 p-4 space-y-3 shadow-xl">
            <div className="flex items-center gap-2 text-yellow-300">
              <AlertTriangle className="size-4" />
              <span className="text-sm font-semibold">Persist review required</span>
            </div>
            {!confirm.summary.allowAllConnect && confirm.summary.denyConnect > 0 && confirm.summary.allowConnect === 0 && (
              <p className="text-xs text-slate-300/80">
                No default network allow detected and {confirm.summary.denyConnect} deny connect rule(s) present. This can cut off connectivity.
              </p>
            )}
            {confirm.issues && confirm.issues.length > 0 && (
              <div className="rounded-md border border-red-500/30 bg-red-950/30 p-2">
                <div className="text-xs font-semibold text-red-300 mb-1">Lint errors ({confirm.issues.length})</div>
                <ul className="list-disc ml-4 space-y-1 max-h-40 overflow-auto">
                  {confirm.issues.map((issue, idx) => (
                    <li key={idx} className="text-[11px] text-red-200/90">
                      <span className="font-mono text-red-300">{issue.code}</span>: {issue.message}
                      {issue.suggestion && <span className="text-slate-300/80"> — {issue.suggestion}</span>}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="outline" className="border-slate-500/40" onClick={() => setConfirm(null)}>
                Cancel
              </Button>
              <Button
                size="sm"
                className="border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/20"
                variant="outline"
                onClick={async () => {
                  setConfirm(null);
                  const ok = await persistCedar(editorDraft, true);
                  if (ok) {
                    if (enforcementMode === "enforce") {
                      await applyEnforce();
                      contextShowNotice("Saved and applied");
                    } else {
                      contextShowNotice("Saved");
                    }
                  }
                }}
              >
                Save
              </Button>
            </div>
          </div>
        </div>
      )}

      {notice && (
        <div className="fixed bottom-4 right-4 z-50">
          <div className="rounded-md border border-green-400/30 bg-slate-900/90 text-green-300 shadow-lg px-3 py-2 text-xs">
            {notice}
          </div>
        </div>
      )}
    </section>
  );
}
