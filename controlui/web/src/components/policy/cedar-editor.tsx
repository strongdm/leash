"use client";

import { useCallback, useEffect, useState, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";
import { validateCedarPolicy, type LintIssue } from "@/lib/policy/api";
import { AlertTriangle, Clipboard, Download } from "lucide-react";
import Editor from "react-simple-code-editor";
import type { HLJSApi } from "highlight.js";
import { loadCedarHighlighter } from "@/lib/highlighting";

type Props = {
  showHeader?: boolean;
};

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
  const [highlighter, setHighlighter] = useState<HLJSApi | null>(null);

  // Initialize draft from server data if empty
  useEffect(() => {
    if (editorDraft.trim() === "") {
      const initialDraft = cedarRuntime || cedarFile || cedarBaseline || "";
      setEditorDraft(initialDraft);
    }
  }, [cedarRuntime, cedarFile, cedarBaseline, editorDraft, setEditorDraft]);

  useEffect(() => {
    let cancelled = false;
    loadCedarHighlighter()
      .then((hl) => {
        if (!cancelled) setHighlighter(hl);
      })
      .catch(() => {
        if (!cancelled) setHighlighter(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const highlightCedar = useCallback(
    (code: string) => {
      if (!highlighter) {
        return escapeHtml(code);
      }
      try {
        return highlighter.highlight(code, { language: "cedar" }).value;
      } catch {
        return escapeHtml(code);
      }
    },
    [highlighter],
  );

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

  const [confirm, setConfirm] = useState<{
    summary: { allowAllConnect: boolean; allowConnect: number; denyConnect: number };
    issues?: LintIssue[];
    show: boolean;
  } | null>(null);

  const [copied, setCopied] = useState(false);
  const [showShortcutTitle, setShowShortcutTitle] = useState(false);
  const shortcutHoverTimerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timer = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(timer);
  }, [copied]);

  useEffect(() => {
    return () => {
      if (shortcutHoverTimerRef.current !== null) {
        window.clearTimeout(shortcutHoverTimerRef.current);
      }
    };
  }, []);

  const copyEditorContents = useCallback(async () => {
    if (typeof navigator === "undefined" || !navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(editorDraft);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }, [editorDraft]);

  const onDownloadPolicy = useCallback(async () => {
    const contents = editorDraft.trim() || cedarRuntime.trim() || cedarFile.trim() || cedarBaseline.trim();

    if (!contents || typeof window === "undefined") {
      return;
    }

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

  const startPermissive = () => {
    if (!cedarBaseline) return;
    const next = editorDraft.trim() ? `${editorDraft}\n\n${cedarBaseline}` : cedarBaseline;
    setEditorDraft(next);
    contextShowNotice("Inserted permissive baseline");
  };

  const scheduleShortcutTitle = () => {
    if (shortcutHoverTimerRef.current !== null) {
      return;
    }
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
    if (showShortcutTitle) {
      setShowShortcutTitle(false);
    }
  };

  // Bind Cmd+S / Ctrl+S to Save
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        void onSave();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onSave]);

  return (
    <section className="space-y-3">
      {showHeader && (
        <div className="flex items-center justify-between gap-3">
          <div>
            <label htmlFor="cedar-editor" className="block text-sm font-semibold text-cyan-300 tracking-wide">
              Policy Editor
            </label>
            <p className="text-xs text-slate-300/80">Edit and apply Cedar policy to this running instance.</p>
          </div>
          <TooltipProvider>
            <div className="flex items-center gap-2">
              {notice && <span className="text-xs text-green-400 font-medium">{notice}</span>}
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
                    onClick={onDownloadPolicy}
                    disabled={editorDraft.trim().length === 0}
                    className="h-8 w-8 text-cyan-200 hover:text-cyan-100 hover:bg-cyan-500/10 disabled:opacity-30"
                  >
                    <Download className="size-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Download policy</TooltipContent>
              </Tooltip>
              <Button size="sm" variant="outline" className="border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/20" onClick={startPermissive}>
                Start Permissive
              </Button>
            </div>
          </TooltipProvider>
        </div>
      )}

      <Editor
        textareaId="cedar-editor"
        value={editorDraft}
        onValueChange={setEditorDraft}
        highlight={highlightCedar}
        padding={12}
        className="cedar-highlight w-full text-cyan-200"
        style={{ minHeight: 180 }}
        placeholder={`permit (principal, action == Action::"NetworkConnect", resource == Host::"api.example.com");`}
        tabSize={2}
      />

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
                const s = await validateCedarPolicy(editorDraft);
                const lintErrors = (s.issues || []).filter(i => i.severity === "error");
                if (lintErrors.length > 0 || (!s.allowAllConnect && s.denyConnect > 0 && s.allowConnect === 0)) {
                  setConfirm({ summary: { allowAllConnect: s.allowAllConnect, allowConnect: s.allowConnect, denyConnect: s.denyConnect }, issues: lintErrors, show: true });
                  return;
                }
                await onSave();
              } catch {
                setConfirm({ summary: { allowAllConnect: false, allowConnect: 0, denyConnect: 0 }, show: true });
              }
            }}
            disabled={submitting || editorDraft.trim().length === 0}
            className="border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/20"
            variant="outline"
            title={showShortcutTitle ? "Shortcut: Cmd+S / Ctrl+S" : undefined}
            onMouseEnter={scheduleShortcutTitle}
            onMouseLeave={clearShortcutTitle}
            onFocus={scheduleShortcutTitle}
            onBlur={clearShortcutTitle}
          >
            {submitting ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
      {/* Confirm modal for risky persist */}
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
                  {confirm.issues.slice(0, 5).map((i, idx) => (
                    <li key={idx} className="text-[11px] text-red-200/90">
                      <span className="font-mono text-red-300">{i.code}</span>: {i.message}
                      {i.suggestion && <span className="text-slate-300/80"> — {i.suggestion}</span>}
                    </li>
                  ))}
                  {confirm.issues.length > 5 && (
                    <li className="text-[11px] text-red-200/80">…and {confirm.issues.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="outline" className="border-slate-500/40" onClick={() => setConfirm(null)}>Cancel</Button>
              <Button size="sm" className="border-cyan-500/40 text-cyan-200 hover:bg-cyan-500/20" variant="outline" onClick={async () => { setConfirm(null); const ok = await persistCedar(editorDraft, true); if (ok) { if (enforcementMode === "enforce") { await applyEnforce(); contextShowNotice("Saved and applied"); } else { contextShowNotice("Saved"); } } }}>
                Save
              </Button>
            </div>
          </div>
        </div>
      )}
      {/* Toast */}
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

const HTML_ESCAPE_LOOKUP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => HTML_ESCAPE_LOOKUP[character] ?? character);
}
