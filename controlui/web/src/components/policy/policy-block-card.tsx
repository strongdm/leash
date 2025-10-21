"use client";

import { useState } from "react";
import clsx from "clsx";
import { ShieldCheck, ShieldX, Copy, Check, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";
import type { PolicyLine } from "@/lib/policy/api";
import { deletePolicyLine } from "@/lib/policy/api";

export default function PolicyBlockCard({ line, onRemoved }: { line: PolicyLine; onRemoved?: (id: string) => void }) {
  const [copied, setCopied] = useState(false);
  const [removing, setRemoving] = useState(false);
  const { refresh, showNotice, enforcementMode } = usePolicyBlocksContext();
  const isAllow = line.effect === "permit";
  const isPermissive = enforcementMode === "permit-all";

  const containerClass = clsx(
    "flex items-center gap-2 px-3 py-2 rounded border backdrop-blur transition-colors group",
    isPermissive ? "border-slate-600/50 bg-slate-900/40 hover:border-slate-500/60" : "border-cyan-500/30 bg-slate-900/50 hover:border-cyan-500/50",
  );
  const textClass = clsx(
    "text-sm truncate flex-1 min-w-0",
    isPermissive ? "text-slate-300/80" : "text-cyan-300",
  );
  const allowIconClass = clsx(
    "size-4 flex-shrink-0",
    isPermissive ? "text-slate-400" : "text-green-400",
  );
  const denyIconClass = clsx(
    "size-4 flex-shrink-0",
    isPermissive ? "text-slate-400" : "text-red-400",
  );

  const effectIcon = isAllow ?
    <ShieldCheck className={allowIconClass} /> :
    <ShieldX className={denyIconClass} />;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(line.cedar);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const handleRemove = async () => {
    try {
      setRemoving(true);
      await deletePolicyLine({ id: line.id, cedar: line.cedar });
      await refresh();
      showNotice("Policy removed");
      onRemoved?.(line.id);
    } catch (err) {
      console.error("Failed to remove policy:", err);
    } finally {
      setRemoving(false);
    }
  };

  return (
    <div className={containerClass}>
      {effectIcon}
      <div className={textClass} title={line.humanized}>
        {line.humanized}
      </div>
      <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="icon"
                variant="ghost"
                onClick={handleCopy}
                className="h-6 w-6 text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/10"
              >
                {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              Copy Cedar
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="icon"
                variant="ghost"
                onClick={handleRemove}
                disabled={removing}
                className="h-6 w-6 text-red-400 hover:text-red-300 hover:bg-red-500/10 disabled:opacity-50"
              >
                <Trash2 className="size-3" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              Remove
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>
    </div>
  );
}
