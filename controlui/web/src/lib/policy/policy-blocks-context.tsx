"use client";

import React, { createContext, useContext, useReducer, useCallback, useEffect, useRef } from "react";
import type { ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  usePolicyQuery,
  usePersistCedarMutation,
  usePermitAllMutation,
  useEnforceMutation,
  usePatchPoliciesMutation,
  policyKeys,
  type PolicyQueryData,
} from "./use-policy-query";
import {
  policyUIReducer,
  initialPolicyUIState,
} from "./policy-ui-reducer";
import type { PolicyBlock } from "./types";
import { policiesToBlocks, type PatchPoliciesRequest } from "./api";
import { useDataSource, useLatestPolicySnapshot } from "@/lib/mock/sim";

type PolicyBlocksContextValue = {
  // Server state (from React Query)
  blocks: PolicyBlock[];
  blocksActive: PolicyBlock[];
  blocksRuntime: PolicyBlock[];
  blocksFile: PolicyBlock[];
  blocksDraft: PolicyBlock[];
  blocksPersisted: PolicyBlock[];
  cedarRuntime: string;
  cedarFile: string;
  cedarBaseline: string;
  enforcementMode: "enforce" | "permit-all";
  loading: boolean;
  loadError: string | null;

  // UI state (from reducer)
  editorDraft: string;
  editorOpen: boolean;
  notice: string | null;

  // Mutation states
  submitting: boolean;
  submitError: string | null;

  // Actions
  setEditorDraft: (draft: string) => void;
  toggleEditor: () => void;
  openEditor: () => void;
  closeEditor: () => void;
  showNotice: (message: string) => void;
  clearNotice: () => void;

  // Mutations
  persistCedar: (cedar?: string, force?: boolean) => Promise<boolean>;
  setPermitAll: () => Promise<boolean>;
  applyEnforce: () => Promise<boolean>;
  refresh: () => Promise<PolicyQueryData | undefined>;
  patchPolicies: (request: PatchPoliciesRequest) => Promise<boolean>;
};

const PolicyBlocksContext = createContext<PolicyBlocksContextValue | null>(null);

export function PolicyBlocksProvider({ children }: { children: ReactNode }) {
  // UI state managed by reducer
  const [uiState, dispatch] = useReducer(policyUIReducer, initialPolicyUIState);
  const lastSyncedDraftRef = useRef<string>("");

  // Server state managed by React Query
  const queryClient = useQueryClient();
  const { data, isLoading, error, refetch } = usePolicyQuery();
  const persistMutation = usePersistCedarMutation();
  const permitAllMutation = usePermitAllMutation();
  const enforceMutation = useEnforceMutation();
  const patchMutation = usePatchPoliciesMutation();
  const latestPolicySnapshot = useLatestPolicySnapshot();
  const { mode, status, connectionVersion } = useDataSource();
  const isLive = mode === "live";

  // Initialize editor draft from server data when it arrives
  useEffect(() => {
    if (data && uiState.editorDraft.trim() === "") {
      const initialDraft = data.cedarRuntime || data.cedarFile || data.cedarBaseline || "";
      if (initialDraft) {
        dispatch({ type: "INIT_DRAFT", payload: initialDraft });
        lastSyncedDraftRef.current = initialDraft;
      }
    }
  }, [data, uiState.editorDraft]);

  // UI actions
  const setEditorDraft = useCallback((draft: string) => {
    dispatch({ type: "SET_DRAFT", payload: draft });
  }, []);

  const toggleEditor = useCallback(() => {
    dispatch({ type: "TOGGLE_EDITOR" });
  }, []);

  const openEditor = useCallback(() => {
    dispatch({ type: "OPEN_EDITOR" });
  }, []);

  const closeEditor = useCallback(() => {
    dispatch({ type: "CLOSE_EDITOR" });
  }, []);

  const showNotice = useCallback((message: string) => {
    dispatch({ type: "SHOW_NOTICE", payload: message });
    setTimeout(() => dispatch({ type: "CLEAR_NOTICE" }), 3000);
  }, []);

  const clearNotice = useCallback(() => {
    dispatch({ type: "CLEAR_NOTICE" });
  }, []);

  const selectDraftFromData = useCallback((payload: {
    cedarRuntime?: string;
    cedarFile?: string;
    cedarBaseline?: string;
  }) => {
    const runtime = payload.cedarRuntime?.trim() ?? "";
    const file = payload.cedarFile?.trim() ?? "";
    const baseline = payload.cedarBaseline ?? "";
    const nextDraft = runtime || file || baseline;
    const trimmedNext = nextDraft.trim();
    const trimmedCurrent = uiState.editorDraft.trim();
    const trimmedSynced = lastSyncedDraftRef.current.trim();

    // If the user has a draft differing from the last synced version, avoid overwriting.
    if (trimmedCurrent !== "" && trimmedCurrent !== trimmedSynced && trimmedCurrent !== trimmedNext) {
      lastSyncedDraftRef.current = nextDraft;
      return;
    }

    if (trimmedNext !== "" && trimmedNext !== trimmedCurrent) {
      dispatch({ type: "SET_DRAFT", payload: nextDraft });
    }

    lastSyncedDraftRef.current = nextDraft;
  }, [uiState.editorDraft]);

  useEffect(() => {
    if (!latestPolicySnapshot) {
      return;
    }
    const policies = latestPolicySnapshot.policies;
    if (!policies) {
      return;
    }

    const {
      blocksActive,
      blocksRuntime,
      blocksFile,
      blocksRuntimeOnly,
      blocksFileOnly,
    } = policiesToBlocks(policies);

    queryClient.setQueryData(policyKeys.detail(), {
      blocks: blocksActive,
      blocksActive,
      blocksRuntime,
      blocksFile,
      blocksDraft: blocksRuntimeOnly,
      blocksPersisted: blocksFileOnly,
      cedarRuntime: policies.cedarRuntime || "",
      cedarFile: policies.cedarFile || "",
      cedarBaseline: policies.cedarBaseline || "",
      enforcementMode: (policies.enforcementMode ?? "enforce") as "enforce" | "permit-all",
    });

    selectDraftFromData({
      cedarRuntime: policies.cedarRuntime,
      cedarFile: policies.cedarFile,
      cedarBaseline: policies.cedarBaseline,
    });
  }, [latestPolicySnapshot, queryClient, selectDraftFromData]);

  // Mutation wrappers
  const persistCedar = useCallback(
    async (cedar?: string, force = false): Promise<boolean> => {
      try {
        const data = await persistMutation.mutateAsync({ cedar, force });
        if (data) {
          selectDraftFromData({
            cedarRuntime: data.cedarRuntime,
            cedarFile: data.cedarFile,
            cedarBaseline: data.cedarBaseline,
          });
        }
        return true;
      } catch (err) {
        console.error("Failed to persist Cedar:", err);
        return false;
      }
    },
    [persistMutation, selectDraftFromData]
  );

  const setPermitAll = useCallback(async (): Promise<boolean> => {
    try {
      const data = await permitAllMutation.mutateAsync();
      if (data) {
        selectDraftFromData({
          cedarRuntime: data.cedarRuntime,
          cedarFile: data.cedarFile,
          cedarBaseline: data.cedarBaseline,
        });
      }
      return true;
    } catch (err) {
      console.error("Failed to set permit all:", err);
      return false;
    }
  }, [permitAllMutation, selectDraftFromData]);

  const applyEnforce = useCallback(async (): Promise<boolean> => {
    try {
      const data = await enforceMutation.mutateAsync();
      if (data) {
        selectDraftFromData({
          cedarRuntime: data.cedarRuntime,
          cedarFile: data.cedarFile,
          cedarBaseline: data.cedarBaseline,
        });
      }
      return true;
    } catch (err) {
      console.error("Failed to apply enforce:", err);
      return false;
    }
  }, [enforceMutation, selectDraftFromData]);

  const patchPolicies = useCallback(async (request: PatchPoliciesRequest): Promise<boolean> => {
    try {
      const data = await patchMutation.mutateAsync(request);
      if (data) {
        selectDraftFromData({
          cedarRuntime: data.cedarRuntime,
          cedarFile: data.cedarFile,
          cedarBaseline: data.cedarBaseline,
        });
      }
      return true;
    } catch (err) {
      console.error("Failed to patch policies:", err);
      return false;
    }
  }, [patchMutation, selectDraftFromData]);

  const refresh = useCallback(async (): Promise<PolicyQueryData | undefined> => {
    const result = await refetch();
    if (result.data) {
      selectDraftFromData({
        cedarRuntime: result.data.cedarRuntime,
        cedarFile: result.data.cedarFile,
        cedarBaseline: result.data.cedarBaseline,
      });
    }
    return result.data;
  }, [refetch, selectDraftFromData]);

  useEffect(() => {
    if (!isLive) {
      return;
    }
    if (connectionVersion === 0) {
      return;
    }
    if (status !== "ready") {
      return;
    }
    void refetch();
  }, [isLive, connectionVersion, status, refetch]);

  // Derive defaults for data
  const safeData: PolicyQueryData = data || {
    blocks: [],
    blocksActive: [],
    blocksRuntime: [],
    blocksFile: [],
    blocksDraft: [],
    blocksPersisted: [],
    cedarRuntime: "",
    cedarFile: "",
    cedarBaseline: "",
    enforcementMode: "enforce",
  };

  // Combine mutation states
  const submitting =
    persistMutation.isPending || permitAllMutation.isPending || enforceMutation.isPending || patchMutation.isPending;
  const submitError =
    persistMutation.error?.message ||
    permitAllMutation.error?.message ||
    enforceMutation.error?.message ||
    patchMutation.error?.message ||
    null;

  const value: PolicyBlocksContextValue = {
    // Server state
    ...safeData,
    loading: isLoading,
    loadError: error?.message || null,

    // UI state
    editorDraft: uiState.editorDraft,
    editorOpen: uiState.editorOpen,
    notice: uiState.notice,

    // Mutation states
    submitting,
    submitError,

    // Actions
    setEditorDraft,
    toggleEditor,
    openEditor,
    closeEditor,
    showNotice,
    clearNotice,

    // Mutations
    persistCedar,
    setPermitAll,
    applyEnforce,
    patchPolicies,
    refresh,
  };

  return (
    <PolicyBlocksContext.Provider value={value}>
      {children}
    </PolicyBlocksContext.Provider>
  );
}

export function usePolicyBlocksContext(): PolicyBlocksContextValue {
  const ctx = useContext(PolicyBlocksContext);
  if (!ctx) {
    throw new Error("usePolicyBlocksContext must be used within PolicyBlocksProvider");
  }
  return ctx;
}
