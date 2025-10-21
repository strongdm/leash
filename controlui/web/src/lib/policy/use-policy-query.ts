"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useDataSource } from "@/lib/mock/sim";
import {
  fetchPolicyBlocks,
  persistCedarPolicy,
  setPermitAllMode,
  applyEnforceMode,
  patchPolicies,
  type PatchPoliciesRequest,
} from "./api";
import { getMockPolicyBlocks } from "./mock";
import type { PolicyBlock } from "./types";

export type PolicyQueryData = {
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
};

const BASELINE_FALLBACK = `// Exploration baseline for interactive discovery
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
when { resource in [ Dir::"/" ] };

permit (principal, action == Action::"ProcessExec", resource)
when { resource in [ Dir::"/" ] };

permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"*" ] };`;

// Query key factory for consistency
export const policyKeys = {
  all: ["policies"] as const,
  detail: () => [...policyKeys.all, "detail"] as const,
};

/**
 * Main query hook for fetching policy blocks
 * Automatically handles mock vs. live mode
 */
export function usePolicyQuery() {
  const { mode } = useDataSource();
  const isSimulation = mode === "sim";

  return useQuery({
    queryKey: policyKeys.detail(),
    queryFn: async (): Promise<PolicyQueryData> => {
      if (isSimulation) {
        const mock = getMockPolicyBlocks();
        return {
          blocks: mock,
          blocksActive: mock,
          blocksRuntime: [],
          blocksFile: mock,
          blocksDraft: [],
          blocksPersisted: mock,
          cedarRuntime: "",
          cedarFile: "",
          cedarBaseline: BASELINE_FALLBACK,
          enforcementMode: "enforce",
        };
      }

      const remote = await fetchPolicyBlocks();
      return {
        blocks: remote.blocks,
        blocksActive: remote.blocksActive,
        blocksRuntime: remote.blocksRuntime,
        blocksFile: remote.blocksFile,
        blocksDraft: remote.blocksRuntimeOnly,
        blocksPersisted: remote.blocksFileOnly,
        cedarRuntime: remote.cedarRuntime || "",
        cedarFile: remote.cedarFile || "",
        cedarBaseline: remote.cedarBaseline || BASELINE_FALLBACK,
        enforcementMode: remote.enforcementMode,
      };
    },
    enabled: true,
  });
}

/**
 * Mutation for persisting Cedar policy
 */
export function usePersistCedarMutation() {
  const queryClient = useQueryClient();
  const { mode } = useDataSource();
  const isSimulation = mode === "sim";

  return useMutation({
    mutationFn: async ({
      cedar,
      force = false,
    }: {
      cedar?: string;
      force?: boolean;
    }) => {
      if (isSimulation) {
        throw new Error("Switch to live mode to persist policy.");
      }
      return await persistCedarPolicy(cedar, undefined, force);
    },
    onSuccess: (data) => {
      // Update cache with new data
      queryClient.setQueryData(policyKeys.detail(), {
        blocks: data.blocks,
        blocksActive: data.blocksActive,
        blocksRuntime: data.blocksRuntime,
        blocksFile: data.blocksFile,
        blocksDraft: data.blocksRuntimeOnly,
        blocksPersisted: data.blocksFileOnly,
        cedarRuntime: data.cedarRuntime || "",
        cedarFile: data.cedarFile || "",
        cedarBaseline: data.cedarBaseline || BASELINE_FALLBACK,
        enforcementMode: data.enforcementMode,
      });
    },
  });
}

/**
 * Mutation for setting Permit All mode
 */
export function usePermitAllMutation() {
  const queryClient = useQueryClient();
  const { mode } = useDataSource();
  const isSimulation = mode === "sim";

  return useMutation({
    mutationFn: async () => {
      if (isSimulation) {
        throw new Error("Switch to live mode to apply policy.");
      }
      await setPermitAllMode();
      // Fetch fresh data after mode change
      return await fetchPolicyBlocks();
    },
    onSuccess: (data) => {
      queryClient.setQueryData(policyKeys.detail(), {
        blocks: data.blocks,
        blocksActive: data.blocksActive,
        blocksRuntime: data.blocksRuntime,
        blocksFile: data.blocksFile,
        blocksDraft: data.blocksRuntimeOnly,
        blocksPersisted: data.blocksFileOnly,
        cedarRuntime: data.cedarRuntime || "",
        cedarFile: data.cedarFile || "",
        cedarBaseline: data.cedarBaseline || BASELINE_FALLBACK,
        enforcementMode: data.enforcementMode,
      });
    },
  });
}

/**
 * Mutation for applying Enforce mode
 */
export function useEnforceMutation() {
  const queryClient = useQueryClient();
  const { mode } = useDataSource();
  const isSimulation = mode === "sim";

  return useMutation({
    mutationFn: async () => {
      if (isSimulation) {
        throw new Error("Switch to live mode to apply policy.");
      }
      await applyEnforceMode();
      // Fetch fresh data after mode change
      return await fetchPolicyBlocks();
    },
    onSuccess: (data) => {
      queryClient.setQueryData(policyKeys.detail(), {
        blocks: data.blocks,
        blocksActive: data.blocksActive,
        blocksRuntime: data.blocksRuntime,
        blocksFile: data.blocksFile,
        blocksDraft: data.blocksRuntimeOnly,
        blocksPersisted: data.blocksFileOnly,
        cedarRuntime: data.cedarRuntime || "",
        cedarFile: data.cedarFile || "",
        cedarBaseline: data.cedarBaseline || BASELINE_FALLBACK,
        enforcementMode: data.enforcementMode,
      });
    },
  });
}

/**
 * Mutation for applying incremental policy changes via PATCH
 */
export function usePatchPoliciesMutation() {
  const queryClient = useQueryClient();
  const { mode } = useDataSource();
  const isSimulation = mode === "sim";

  return useMutation({
    mutationFn: async (request: PatchPoliciesRequest) => {
      if (isSimulation) {
        throw new Error("Switch to live mode to apply policy.");
      }
      return await patchPolicies(request);
    },
    onSuccess: (data) => {
      queryClient.setQueryData(policyKeys.detail(), {
        blocks: data.blocks,
        blocksActive: data.blocksActive,
        blocksRuntime: data.blocksRuntime,
        blocksFile: data.blocksFile,
        blocksDraft: data.blocksRuntimeOnly,
        blocksPersisted: data.blocksFileOnly,
        cedarRuntime: data.cedarRuntime || "",
        cedarFile: data.cedarFile || "",
        cedarBaseline: data.cedarBaseline || BASELINE_FALLBACK,
        enforcementMode: data.enforcementMode,
      });
    },
  });
}
