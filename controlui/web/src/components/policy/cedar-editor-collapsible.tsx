"use client";

import { useEffect, useState } from "react";
import { ChevronDown, Clipboard, Download } from "lucide-react";
import CedarEditor from "@/components/policy/cedar-editor";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";

type Props = {
  defaultOpen?: boolean;
};

const safeTrim = (value?: string | null) => value?.trim() ?? "";

export default function CedarEditorCollapsible({ defaultOpen = false }: Props) {
  const { submitError, cedarRuntime, cedarFile, cedarBaseline, editorDraft } = usePolicyBlocksContext();
  const [open, setOpen] = useState<boolean>(defaultOpen);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const handleToggleShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === "e") {
        event.preventDefault();
        setOpen((prev) => !prev);
      }
    };

    window.addEventListener("keydown", handleToggleShortcut);
    return () => window.removeEventListener("keydown", handleToggleShortcut);
  }, []);

  const draft = editorDraft;
  const trimmedDraft = draft.trim();
  const downloadSource = trimmedDraft !== "" ? draft : cedarRuntime || cedarFile || cedarBaseline || "";
  const hasDownloadSource = safeTrim(downloadSource).length > 0;

  // If a submit error occurs, pop the editor open for visibility.
  useEffect(() => {
    if (submitError) setOpen(true);
  }, [submitError]);

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timer = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const copyEditorContents = async () => {
    if (typeof navigator === "undefined" || !navigator.clipboard) {
      return;
    }
    try {
      const value = hasDownloadSource ? downloadSource : "";
      if (!value) {
        setCopied(false);
        return;
      }
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  const onDownloadPolicy = async () => {
    const contents =
      draft.trim() ||
      safeTrim(cedarRuntime) ||
      safeTrim(cedarFile) ||
      safeTrim(cedarBaseline);

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
  };

  return (
    <div className="rounded-lg border border-cyan-500/30 bg-slate-900/60">
      <div
        className="w-full px-4 py-3 flex items-center justify-between gap-3 text-left hover:bg-slate-900/70"
        role="button"
        tabIndex={0}
        aria-expanded={open}
        aria-controls="cedar-editor-panel"
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpen((v) => !v);
          }
        }}
      >
        <div className="flex-1">
          <div className="text-sm font-semibold text-cyan-300 tracking-wide">Policy Editor</div>
          <p className="text-xs text-slate-300/80">Paste Cedar policy to update the running instance.</p>
        </div>
        <TooltipProvider>
          <div className="flex items-center gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label="Copy policy to clipboard"
                  className="h-8 w-8 text-cyan-200 hover:text-cyan-100 hover:bg-cyan-500/10 disabled:opacity-30"
                  disabled={!hasDownloadSource}
                  onClick={(e) => {
                    e.stopPropagation();
                    if (!hasDownloadSource) return;
                    void copyEditorContents();
                  }}
                >
                  <Clipboard className="size-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Copy policy to clipboard</TooltipContent>
            </Tooltip>
            {copied && <span className="text-[11px] text-cyan-200">Copied</span>}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label="Download policy"
                  className="h-8 w-8 text-cyan-200 hover:text-cyan-100 hover:bg-cyan-500/10 disabled:opacity-30"
                  disabled={!hasDownloadSource}
                  onClick={(e) => {
                    e.stopPropagation();
                    if (!hasDownloadSource) return;
                    void onDownloadPolicy();
                  }}
                >
                  <Download className="size-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Download policy</TooltipContent>
            </Tooltip>
            <ChevronDown className={`size-4 transition-transform ${open ? "rotate-180" : "rotate-0"}`} />
          </div>
        </TooltipProvider>
      </div>

      {open && (
        <div id="cedar-editor-panel" className="px-4 pb-4">
          <CedarEditor showHeader={false} />
        </div>
      )}
    </div>
  );
}
