"use client";

import { useCallback, useEffect, useState, useRef } from "react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";
import { useSingle } from "@/lib/single/store";

export default function SingleHeader() {
  const {
    cedarFile,
    cedarRuntime,
    cedarBaseline,
    persistCedar,
    setPermitAll,
    applyEnforce,
    enforcementMode,
    submitting,
    editorDraft,
  } = usePolicyBlocksContext();
  const { setMode } = useSingle();
  const [showSubmitting, setShowSubmitting] = useState(false);
  const submittingStartTimeRef = useRef<number | null>(null);

  // Handle minimum display time for "Applying..." message
  useEffect(() => {
    if (submitting) {
      submittingStartTimeRef.current = Date.now();
      setShowSubmitting(true);
    } else if (submittingStartTimeRef.current !== null) {
      const elapsed = Date.now() - submittingStartTimeRef.current;
      const remaining = Math.max(0, 500 - elapsed);

      const timer = setTimeout(() => {
        setShowSubmitting(false);
        submittingStartTimeRef.current = null;
      }, remaining);

      return () => clearTimeout(timer);
    }
  }, [submitting]);

  const onPermitAll = useCallback(async () => {
    // Switch to Permit All mode (runtime-only permissive; file/persisted untouched)
    const ok = await setPermitAll();
    if (ok) setMode("record");
  }, [setPermitAll, setMode]);

  const onEnforce = useCallback(async () => {
    // Prefer editor draft (current user intent) > file (persisted) > runtime
    const cedar = editorDraft.trim() || cedarFile.trim() || cedarRuntime.trim() || cedarBaseline.trim();
    if (!cedar) {
      // Nothing to enforce yet; keep mode visual but do not mutate runtime.
      setMode("enforce");
      return;
    }
    // Persist to file (source of truth), then switch to Enforce mode
    // React Query will automatically refresh the state, no manual refresh needed
    const persisted = await persistCedar(cedar, true);
    if (persisted) {
      const ok = await applyEnforce();
      if (ok) {
        setMode("enforce");
      }
    }
  }, [editorDraft, cedarFile, cedarRuntime, cedarBaseline, persistCedar, applyEnforce, setMode]);

  const handleEnforcementChange = useCallback(async (value: string) => {
    if (submitting) return;
    if (value === "enforce") {
      await onEnforce();
    } else {
      await onPermitAll();
    }
  }, [submitting, onEnforce, onPermitAll]);

  return (
    <div className="flex items-center justify-between px-4 py-3 border rounded-lg border-cyan-500/30 bg-slate-900/50 backdrop-blur">
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium text-cyan-300/90">Enforcement Mode</span>
        {showSubmitting && <span className="text-xs text-cyan-400/60">Applying…</span>}
      </div>
      <div className="flex items-center gap-3">
        <Tabs
          value={enforcementMode === "enforce" ? "enforce" : "permit-all"}
          onValueChange={handleEnforcementChange}
        >
          <TabsList className="bg-slate-900/80 border border-cyan-500/30">
            <TabsTrigger
              value="permit-all"
              disabled={submitting}
              className="data-[state=active]:bg-amber-500/20 data-[state=active]:text-amber-300 data-[state=active]:border-amber-500/40"
            >
              Permissive
            </TabsTrigger>
            <TabsTrigger
              value="enforce"
              disabled={submitting}
              className="data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-300 data-[state=active]:border-emerald-500/40"
            >
              Enforcing
            </TabsTrigger>
          </TabsList>
        </Tabs>
      </div>
    </div>
  );
}
