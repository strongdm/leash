"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useDataSource } from "@/lib/mock/sim";
import type { PolicyBlock } from "./types";
import { fetchPolicyBlocks, persistCedarPolicy, setPermitAllMode, applyEnforceMode } from "./api";
import { getMockPolicyBlocks } from "./mock";

type PolicyBlocksState = {
  blocks: PolicyBlock[]; // active (back-compat)
  blocksActive: PolicyBlock[];
  blocksRuntime: PolicyBlock[];
  blocksFile: PolicyBlock[];
  blocksDraft: PolicyBlock[]; // runtimeOnly (not persisted)
  blocksPersisted: PolicyBlock[]; // fileOnly (persisted)
  cedarRuntime: string;
  cedarFile: string;
  loading: boolean;
  loadError: string | null;
  submitting: boolean;
  submitError: string | null;
  persistCedar: (cedar?: string, force?: boolean) => Promise<boolean>;
  setPermitAll: () => Promise<boolean>;
  applyEnforce: () => Promise<boolean>;
  refresh: () => Promise<void>;
  enforcementMode: "enforce" | "permit-all";
};

export function usePolicyBlocks(): PolicyBlocksState {
  const { mode, status, connectionVersion } = useDataSource();
  const isSimulation = mode === "sim";

  const [blocks, setBlocks] = useState<PolicyBlock[]>([]);
  const [blocksActive, setBlocksActive] = useState<PolicyBlock[]>([]);
  const [blocksRuntime, setBlocksRuntime] = useState<PolicyBlock[]>([]);
  const [blocksFile, setBlocksFile] = useState<PolicyBlock[]>([]);
  const [blocksDraft, setBlocksDraft] = useState<PolicyBlock[]>([]);
  const [blocksPersisted, setBlocksPersisted] = useState<PolicyBlock[]>([]);
  const [loading, setLoading] = useState(!isSimulation);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [cedarRuntime, setCedarRuntime] = useState<string>("");
  const [cedarFile, setCedarFile] = useState<string>("");
  const [enforcementMode, setEnforcementMode] = useState<"enforce" | "permit-all">("enforce");

  const refresh = useCallback(async () => {
    if (isSimulation) {
      const mock = getMockPolicyBlocks();
      setBlocks(mock);
      setBlocksActive(mock);
      setBlocksRuntime([]);
      setBlocksFile(mock);
      setBlocksDraft([]);
      setBlocksPersisted(mock);
      setLoadError(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setLoadError(null);
    try {
      const remote = await fetchPolicyBlocks();
      setBlocks(remote.blocks);
      setBlocksActive(remote.blocksActive);
      setBlocksRuntime(remote.blocksRuntime);
      setBlocksFile(remote.blocksFile);
      setBlocksDraft(remote.blocksRuntimeOnly);
      setBlocksPersisted(remote.blocksFileOnly);
      setCedarRuntime(remote.cedarRuntime || "");
      setCedarFile(remote.cedarFile || "");
      setEnforcementMode(remote.enforcementMode);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load policies";
      setLoadError(message);
    } finally {
      setLoading(false);
    }
  }, [isSimulation]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (isSimulation) {
      return;
    }
    if (connectionVersion === 0) {
      return;
    }
    if (status !== "ready") {
      return;
    }
    void refresh();
  }, [isSimulation, connectionVersion, status, refresh]);

  const persistCedar = useCallback(async (cedar?: string, force?: boolean) => {
    if (isSimulation) {
      setSubmitError("Switch to live mode to persist policy.");
      return false;
    }
    setSubmitting(true);
    setSubmitError(null);
    try {
      const updated = await persistCedarPolicy((cedar || "").trim() || undefined, undefined, !!force);
      setBlocks(updated.blocks);
      setBlocksActive(updated.blocksActive);
      setBlocksRuntime(updated.blocksRuntime);
      setBlocksFile(updated.blocksFile);
      setBlocksDraft(updated.blocksRuntimeOnly);
      setBlocksPersisted(updated.blocksFileOnly);
      setCedarRuntime(updated.cedarRuntime || "");
      setCedarFile(updated.cedarFile || "");
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to persist policies";
      setSubmitError(message);
      return false;
    } finally {
      setSubmitting(false);
    }
  }, [isSimulation]);

  const setPermitAll = useCallback(async () => {
    if (isSimulation) {
      setSubmitError("Switch to live mode to apply policy.");
      return false;
    }
    setSubmitting(true);
    setSubmitError(null);
    try {
      // Permit All should not overwrite or disturb cedarFile/cards; we still refresh state for Active display.
      await setPermitAllMode();
      const remote = await fetchPolicyBlocks();
      setBlocks(remote.blocks);
      setBlocksActive(remote.blocksActive);
      setBlocksRuntime(remote.blocksRuntime);
      setBlocksFile(remote.blocksFile);
      setBlocksDraft(remote.blocksRuntimeOnly);
      setBlocksPersisted(remote.blocksFileOnly);
      setCedarRuntime(remote.cedarRuntime || "");
      setCedarFile(remote.cedarFile || "");
      setEnforcementMode(remote.enforcementMode);
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to apply permissive policy";
      setSubmitError(message);
      return false;
    } finally {
      setSubmitting(false);
    }
  }, [isSimulation]);

  const applyEnforce = useCallback(async () => {
    if (isSimulation) {
      setSubmitError("Switch to live mode to apply policy.");
      return false;
    }
    setSubmitting(true);
    setSubmitError(null);
    try {
      await applyEnforceMode();
      // Update local state to reflect enforced active/file rules
      const remote = await fetchPolicyBlocks();
      setBlocks(remote.blocks);
      setBlocksActive(remote.blocksActive);
      setBlocksRuntime(remote.blocksRuntime);
      setBlocksFile(remote.blocksFile);
      setBlocksDraft(remote.blocksRuntimeOnly);
      setBlocksPersisted(remote.blocksFileOnly);
      setCedarRuntime(remote.cedarRuntime || "");
      setCedarFile(remote.cedarFile || "");
      setEnforcementMode(remote.enforcementMode);
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to apply enforced policy";
      setSubmitError(message);
      return false;
    } finally {
      setSubmitting(false);
    }
  }, [isSimulation]);

  return useMemo(
    () => ({ 
      blocks,
      blocksActive,
      blocksRuntime,
      blocksFile,
      blocksDraft,
      blocksPersisted,
      cedarRuntime,
      cedarFile,
      loading,
      loadError,
      submitting,
      submitError,
      persistCedar,
      setPermitAll,
      applyEnforce,
      refresh,
      enforcementMode 
    }),
    [
      blocks,
      blocksActive,
      blocksRuntime,
      blocksFile,
      blocksDraft,
      blocksPersisted,
      cedarRuntime,
      cedarFile,
      loading,
      loadError,
      submitting,
      submitError,
      persistCedar,
      setPermitAll,
      applyEnforce,
      refresh,
      enforcementMode
    ],
  );
}
