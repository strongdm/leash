"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Editor, { type Monaco } from "@monaco-editor/react";
import type * as monacoEditor from "monaco-editor";
import { AlertTriangle, Clipboard, Download } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ensureCedarLanguage, CEDAR_LANGUAGE_ID } from "@/lib/policy/cedar-language";
import {
  fetchPolicyCompletions,
  validateCedarPolicy,
  type CompletionItem,
  type LintIssue,
} from "@/lib/policy/api";
import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";

type Props = {
  showHeader?: boolean;
};

type SuggestionHelp = {
  label: string;
  detail?: string;
  documentation?: string;
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
  const [suggestionHelp, setSuggestionHelp] = useState<SuggestionHelp | null>(null);
  const shortcutHoverTimerRef = useRef<number | null>(null);
  const editorRef = useRef<monacoEditor.editor.IStandaloneCodeEditor | null>(null);
  const monacoRef = useRef<Monaco | null>(null);
  const completionDisposableRef = useRef<monacoEditor.IDisposable | null>(null);
  const completionAbortRef = useRef<AbortController | null>(null);
  const isMountedRef = useRef(false);

  const [confirm, setConfirm] = useState<{
    summary: { allowAllConnect: boolean; allowConnect: number; denyConnect: number };
    issues?: LintIssue[];
    show: boolean;
  } | null>(null);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      completionDisposableRef.current?.dispose();
      completionAbortRef.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timer = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(timer);
  }, [copied]);

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

  const registerCompletionProvider = useCallback(
    (monaco: Monaco, editor: monacoEditor.editor.IStandaloneCodeEditor) => {
      completionDisposableRef.current?.dispose();
      completionDisposableRef.current = monaco.languages.registerCompletionItemProvider(CEDAR_LANGUAGE_ID, {
        triggerCharacters: ['"', ':', '.', '/', '(', ',', '=', '!'],
        async provideCompletionItems(model, position, _context, token) {
          if (!isMountedRef.current) {
            return { suggestions: [] };
          }

          const controller = new AbortController();
          completionAbortRef.current?.abort();
          completionAbortRef.current = controller;
          token.onCancellationRequested(() => controller.abort());

          try {
            const response = await fetchPolicyCompletions(
              {
                cedar: model.getValue(),
                cursor: { line: position.lineNumber, column: position.column },
              },
              controller.signal,
            );

            if (controller.signal.aborted) {
              return { suggestions: [] };
            }

            if (response.items.length > 0) {
              const top = response.items[0];
              setSuggestionHelp({
                label: top.label,
                detail: top.detail,
                documentation: top.documentation,
              });
            } else {
              setSuggestionHelp(null);
            }

            const suggestions = response.items.map((item) => mapCompletionItem(monaco, item));
            return { suggestions };
          } catch {
            if (!controller.signal.aborted) {
              setSuggestionHelp(null);
            }
            return { suggestions: [] };
          } finally {
            if (completionAbortRef.current === controller) {
              completionAbortRef.current = null;
            }
          }
        },
      });

      editor.onDidDispose(() => {
        completionDisposableRef.current?.dispose();
        completionAbortRef.current?.abort();
      });
    },
    [],
  );

  const handleBeforeMount = useCallback((monaco: Monaco) => {
    ensureCedarLanguage(monaco);
  }, []);

  const handleMount = useCallback(
    (editor: monacoEditor.editor.IStandaloneCodeEditor, monaco: Monaco) => {
      editorRef.current = editor;
      monacoRef.current = monaco;

      editor.updateOptions({
        fontSize: 13,
        minimap: { enabled: false },
        tabSize: 2,
        insertSpaces: true,
        wordWrap: "on",
        scrollBeyondLastLine: false,
      });

      registerCompletionProvider(monaco, editor);

      // Clear existing markers when mounting to avoid stale warnings.
      const model = editor.getModel();
      if (model) {
        monaco.editor.setModelMarkers(model, "cedar-lint", []);
      }
    },
    [registerCompletionProvider],
  );

  useEffect(() => {
    if (!editorRef.current || !monacoRef.current) {
      return;
    }
    const monaco = monacoRef.current;
    const editor = editorRef.current;
    const model = editor.getModel();
    if (!model) {
      return;
    }

    if (!editorDraft.trim()) {
      monaco.editor.setModelMarkers(model, "cedar-lint", []);
      return;
    }

    const controller = new AbortController();
    const timeout = window.setTimeout(async () => {
      try {
        const summary = await validateCedarPolicy(editorDraft, controller.signal);
        if (controller.signal.aborted || !monacoRef.current) {
          return;
        }
        const markers = createMarkers(monaco, editorDraft, summary.issues ?? []);
        monaco.editor.setModelMarkers(model, "cedar-lint", markers);
      } catch {
        if (!controller.signal.aborted && monacoRef.current) {
          monaco.editor.setModelMarkers(model, "cedar-lint", []);
        }
      }
    }, VALIDATION_DEBOUNCE_MS);

    return () => {
      controller.abort();
      window.clearTimeout(timeout);
    };
  }, [editorDraft]);

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

  const startPermissive = useCallback(() => {
    if (!cedarBaseline) return;
    const next = editorDraft.trim() ? `${editorDraft}\n\n${cedarBaseline}` : cedarBaseline;
    setEditorDraft(next);
    contextShowNotice("Inserted permissive baseline");
  }, [cedarBaseline, editorDraft, setEditorDraft, contextShowNotice]);

  const isEditorEmpty = editorDraft.trim().length === 0;

  const placeholder = useMemo(
    () => 'permit (principal, action == Action::"NetworkConnect", resource == Host::"api.example.com");',
    [],
  );

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
                    className="h-8 w-8 text-cyan-200 hover:text-cyan-100 hover:bg-cyan-500/10"
                    onClick={onDownloadPolicy}
                    disabled={editorDraft.trim().length === 0 && cedarRuntime.trim().length === 0 && cedarFile.trim().length === 0}
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

      <div className="relative border border-cyan-500/30 rounded-md overflow-hidden">
        {isEditorEmpty && (
          <span className="pointer-events-none absolute left-4 top-3 text-xs text-slate-400/70">{placeholder}</span>
        )}
        <Editor
          height="260px"
          defaultLanguage={CEDAR_LANGUAGE_ID}
          language={CEDAR_LANGUAGE_ID}
          value={editorDraft}
          onChange={(value) => setEditorDraft(value ?? "")}
          theme="vs-dark"
          beforeMount={handleBeforeMount}
          onMount={handleMount}
          options={{
            fontFamily: "var(--font-mono, 'JetBrains Mono', 'Fira Code', monospace)",
            fontLigatures: true,
            padding: { top: 12, bottom: 12 },
          }}
        />
      </div>

      {suggestionHelp && (
        <div className="text-xs text-slate-300/80 border border-cyan-500/20 rounded-md bg-slate-900/60 px-3 py-2">
          <span className="font-semibold text-cyan-200">{suggestionHelp.label}</span>
          {suggestionHelp.detail && <span className="ml-2 text-slate-300/70">{suggestionHelp.detail}</span>}
          {suggestionHelp.documentation && (
            <span className="block mt-1 text-slate-400/70 leading-snug">{suggestionHelp.documentation}</span>
          )}
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
                const lintErrors = (summary.issues || []).filter((issue) => issue.severity === "error");
                if (lintErrors.length > 0 || (!summary.allowAllConnect && summary.denyConnect > 0 && summary.allowConnect === 0)) {
                  setConfirm({
                    summary: {
                      allowAllConnect: summary.allowAllConnect,
                      allowConnect: summary.allowConnect,
                      denyConnect: summary.denyConnect,
                    },
                    issues: lintErrors,
                    show: true,
                  });
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
                  {confirm.issues.slice(0, 5).map((issue, idx) => (
                    <li key={idx} className="text-[11px] text-red-200/90">
                      <span className="font-mono text-red-300">{issue.code}</span>: {issue.message}
                      {issue.suggestion && <span className="text-slate-300/80"> — {issue.suggestion}</span>}
                    </li>
                  ))}
                  {confirm.issues.length > 5 && (
                    <li className="text-[11px] text-red-200/80">…and {confirm.issues.length - 5} more</li>
                  )}
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

function mapCompletionItem(monaco: Monaco, item: CompletionItem): monacoEditor.languages.CompletionItem {
  const range = new monaco.Range(item.range.start.line, item.range.start.column, item.range.end.line, item.range.end.column);
  const kind = completionKindFor(monaco, item.kind);
  const suggestion: monacoEditor.languages.CompletionItem = {
    label: item.label,
    kind,
    insertText: item.insertText,
    range,
    sortText: item.sortText,
    detail: item.detail,
    documentation: item.documentation ? { value: item.documentation } : undefined,
    commitCharacters: item.commitCharacters,
  };
  if (item.kind === "snippet") {
    suggestion.insertTextRules = monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet;
  }
  return suggestion;
}

function completionKindFor(monaco: Monaco, kind: CompletionItem["kind"]): monacoEditor.languages.CompletionItemKind {
  const { CompletionItemKind } = monaco.languages;
  const map: Record<CompletionItem["kind"], monacoEditor.languages.CompletionItemKind> = {
    keyword: CompletionItemKind.Keyword,
    action: CompletionItemKind.Function,
    entityType: CompletionItemKind.Class,
    resource: CompletionItemKind.Field,
    conditionKey: CompletionItemKind.Variable,
    snippet: CompletionItemKind.Snippet,
    tool: CompletionItemKind.Interface,
    server: CompletionItemKind.EnumMember,
    header: CompletionItemKind.Property,
  };
  return map[kind] ?? CompletionItemKind.Text;
}

function createMarkers(monaco: Monaco, cedar: string, issues: LintIssue[]): monacoEditor.editor.IMarkerData[] {
  if (!issues.length) {
    return [];
  }
  const lines = cedar.split(/\r?\n/);
  return issues.map((issue) => {
    const line = findPolicyLine(lines, issue.policyId) ?? 1;
    const message = issue.suggestion ? `${issue.message} — ${issue.suggestion}` : issue.message;
    return {
      severity: issue.severity === "error" ? monaco.MarkerSeverity.Error : monaco.MarkerSeverity.Warning,
      startLineNumber: line,
      endLineNumber: line,
      startColumn: 1,
      endColumn: 1,
      message,
      code: issue.code,
    } satisfies monacoEditor.editor.IMarkerData;
  });
}

function findPolicyLine(lines: string[], policyId: string): number | null {
  if (!policyId) {
    return null;
  }
  for (let idx = 0; idx < lines.length; idx += 1) {
    if (lines[idx].includes(policyId)) {
      return idx + 1;
    }
  }
  return null;
}
