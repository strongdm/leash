import type { PolicyBlock, PolicyCategory, PolicyEffect, PolicySource } from "./types";

export type PolicyRuleView = {
  action: PolicyEffect | "deny" | "allow";
  operation: string;
  target: string;
  path?: string;
  hostname?: string;
  ip?: string;
  port?: number;
  isWildcard?: boolean;
  rule: string;
};

export type HttpRuleView = {
  host: string;
  header: string;
  value: string;
  rule: string;
};

export type PolicyLayerView = {
  lsm: PolicyRuleView[];
  http: HttpRuleView[];
};

export type PoliciesResponse = {
  active: PolicyLayerView;
  runtime: PolicyLayerView;
  file: PolicyLayerView;
  cedarRuntime?: string;
  cedarFile?: string;
  cedarBaseline?: string;
  enforcementMode?: "enforce" | "permit-all";
};

export type CedarErrorDetail = {
  message?: string;
  file?: string;
  line?: number;
  column?: number;
  snippet?: string;
  caretStart?: number;
  caretEnd?: number;
  code?: string;
  suggestion?: string;
};

function resolveApiBase(): string {
  if (typeof window !== "undefined") {
    const fromEnv = process.env.NEXT_PUBLIC_LEASH_API_BASE_URL;
    if (fromEnv) return fromEnv.replace(/\/$/, "");

    const { protocol, hostname, port } = window.location;
    if (port === "3000" || port === "") {
      return `${protocol}//${hostname}:18080`;
    }
    return `${protocol}//${hostname}${port ? `:${port}` : ""}`;
  }
  return (process.env.NEXT_PUBLIC_LEASH_API_BASE_URL || "http://127.0.0.1:18080").replace(/\/$/, "");
}

function parseErrorPayload(payload: unknown): { message: string; detail?: CedarErrorDetail } {
  if (!payload) {
    return { message: "" };
  }
  let errorField: unknown = payload;
  if (isRecord(payload) && "error" in payload) {
    errorField = (payload as Record<string, unknown>).error;
  }
  if (typeof errorField === "string") {
    return { message: errorField };
  }
  if (errorField && typeof errorField === "object") {
    const detail = errorField as CedarErrorDetail;
    const message = typeof detail.message === "string" && detail.message.trim().length > 0
      ? detail.message
      : "Policy validation failed";
    return { message, detail };
  }
  return { message: "" };
}

async function handleErrorResponse(res: Response): Promise<never> {
  let message = `Policy API returned ${res.status}`;
  let detail: CedarErrorDetail | undefined;
  try {
    const payload = await res.json();
    const parsed = parseErrorPayload(payload);
    if (parsed.message) {
      message = parsed.message;
    }
    detail = parsed.detail;
  } catch {
    // ignore JSON parse errors
  }
  const err = new Error(message) as Error & { detail?: CedarErrorDetail };
  if (detail) {
    err.detail = detail;
  }
  throw err;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export type PatchPolicyAction = {
  type: string;
  name: string;
  tool?: string;
  server?: string;
};

export type PatchPolicyAdd = {
  cedar?: string;
  effect?: "permit" | "forbid";
  action?: PatchPolicyAction;
};

export type PatchPolicyRemove = {
  id?: string;
  cedar?: string;
};

export type PatchPoliciesRequest = {
  add?: PatchPolicyAdd[];
  remove?: PatchPolicyRemove[];
  applyMode?: "enforce";
};

export type CompletionCursor = {
  line: number;
  column: number;
};

export type CompletionRange = {
  start: CompletionCursor;
  end: CompletionCursor;
};

export type CompletionKind =
  | "keyword"
  | "action"
  | "entityType"
  | "resource"
  | "conditionKey"
  | "snippet"
  | "tool"
  | "server"
  | "header";

export type CompletionItem = {
  label: string;
  kind: CompletionKind;
  insertText: string;
  detail?: string;
  documentation?: string;
  sortText?: string;
  commitCharacters?: string[];
  range: CompletionRange;
};

export type CompletionResponse = {
  items: CompletionItem[];
};

export type CompletionRequest = {
  cedar: string;
  cursor: CompletionCursor;
  maxItems?: number;
  idHints?: {
    tools?: string[];
    servers?: string[];
  };
};

export async function fetchPolicyBlocks(signal?: AbortSignal): Promise<{
  blocks: PolicyBlock[];
  blocksActive: PolicyBlock[];
  blocksRuntime: PolicyBlock[];
  blocksFile: PolicyBlock[];
  blocksRuntimeOnly: PolicyBlock[];
  blocksFileOnly: PolicyBlock[];
  cedarRuntime: string;
  cedarFile: string;
  cedarBaseline: string;
  enforcementMode: "enforce" | "permit-all";
}> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/policies`, {
    method: "GET",
    headers: {
      "Accept": "application/json",
    },
    cache: "no-store",
    signal,
  });

  if (!res.ok) {
    return handleErrorResponse(res);
  }

  const data = (await res.json()) as PoliciesResponse;
  const {
    blocksActive,
    blocksRuntime,
    blocksFile,
    blocksRuntimeOnly,
    blocksFileOnly,
  } = policiesToBlocks(data);
  // For backward compatibility, expose `blocks` as active
  return { 
    blocks: blocksActive,
    blocksActive,
    blocksRuntime,
    blocksFile,
    blocksRuntimeOnly,
    blocksFileOnly,
    cedarRuntime: data.cedarRuntime || "",
    cedarFile: data.cedarFile || "",
    cedarBaseline: data.cedarBaseline || "",
    enforcementMode: (data.enforcementMode ?? "enforce") as "enforce" | "permit-all",
  };
}

export async function fetchPolicyCompletions(request: CompletionRequest, signal?: AbortSignal): Promise<CompletionResponse> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/policies/complete`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(request),
    signal,
  });
  if (!res.ok) {
    return handleErrorResponse(res);
  }
  return (await res.json()) as CompletionResponse;
}

export async function persistCedarPolicy(cedar?: string, signal?: AbortSignal, force?: boolean): Promise<{
  blocks: PolicyBlock[];
  blocksActive: PolicyBlock[];
  blocksRuntime: PolicyBlock[];
  blocksFile: PolicyBlock[];
  blocksRuntimeOnly: PolicyBlock[];
  blocksFileOnly: PolicyBlock[];
  cedarRuntime: string;
  cedarFile: string;
  cedarBaseline: string;
  enforcementMode: "enforce" | "permit-all";
}> {
  const base = resolveApiBase();
  const body = cedar && cedar.trim() ? JSON.stringify({ cedar }) : undefined;
  const q2 = force ? '?force=1' : '';
  const res = await fetch(`${base}/api/policies/persist${q2}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body,
    signal,
  });

  if (!res.ok) {
    return handleErrorResponse(res);
  }

  const data = (await res.json()) as PoliciesResponse;
  const {
    blocksActive,
    blocksRuntime,
    blocksFile,
    blocksRuntimeOnly,
    blocksFileOnly,
  } = policiesToBlocks(data);
  return {
    blocks: blocksActive,
    blocksActive,
    blocksRuntime,
    blocksFile,
    blocksRuntimeOnly,
    blocksFileOnly,
    cedarRuntime: data.cedarRuntime || "",
    cedarFile: data.cedarFile || "",
    cedarBaseline: data.cedarBaseline || "",
    enforcementMode: (data.enforcementMode ?? "enforce") as "enforce" | "permit-all",
  };
}

export async function patchPolicies(request: PatchPoliciesRequest, signal?: AbortSignal): Promise<{
  blocks: PolicyBlock[];
  blocksActive: PolicyBlock[];
  blocksRuntime: PolicyBlock[];
  blocksFile: PolicyBlock[];
  blocksRuntimeOnly: PolicyBlock[];
  blocksFileOnly: PolicyBlock[];
  cedarRuntime: string;
  cedarFile: string;
  cedarBaseline: string;
  enforcementMode: "enforce" | "permit-all";
}> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/policies`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(request ?? {}),
    signal,
  });

  if (!res.ok) {
    return handleErrorResponse(res);
  }

  const data = (await res.json()) as PoliciesResponse;
  const {
    blocksActive,
    blocksRuntime,
    blocksFile,
    blocksRuntimeOnly,
    blocksFileOnly,
  } = policiesToBlocks(data);
  return {
    blocks: blocksActive,
    blocksActive,
    blocksRuntime,
    blocksFile,
    blocksRuntimeOnly,
    blocksFileOnly,
    cedarRuntime: data.cedarRuntime || "",
    cedarFile: data.cedarFile || "",
    cedarBaseline: data.cedarBaseline || "",
    enforcementMode: (data.enforcementMode ?? "enforce") as "enforce" | "permit-all",
  };
}

export async function setPermitAllMode(signal?: AbortSignal): Promise<PoliciesResponse> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/policies/permit-all`, {
    method: "POST",
    headers: { Accept: "application/json" },
    signal,
  });
  if (!res.ok) {
    return handleErrorResponse(res);
  }
  return (await res.json()) as PoliciesResponse;
}

export async function applyEnforceMode(signal?: AbortSignal): Promise<PoliciesResponse> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/policies/enforce-apply`, {
    method: "POST",
    headers: { Accept: "application/json" },
    signal,
  });
  if (!res.ok) {
    return handleErrorResponse(res);
  }
  return (await res.json()) as PoliciesResponse;
}
export type ValidateSummary = {
  allowOpen: number;
  allowExec: number;
  allowConnect: number;
  denyOpen: number;
  denyExec: number;
  denyConnect: number;
  allowAllConnect: boolean;
  issues?: LintIssue[];
};

export type LintIssue = {
  policyId: string;
  severity: "error" | "warning";
  code: string;
  message: string;
  suggestion?: string;
};

export async function validateCedarPolicy(cedar?: string, signal?: AbortSignal): Promise<ValidateSummary> {
  const base = resolveApiBase();
  const body = cedar && cedar.trim() ? JSON.stringify({ cedar }) : "{}";
  const res = await fetch(`${base}/api/policies/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body,
    signal,
  });
  if (!res.ok) {
    return handleErrorResponse(res);
  }
  return (await res.json()) as ValidateSummary;
}

export type PolicyLine = {
  id: string;
  effect: "permit" | "forbid";
  humanized: string;
  cedar: string;
  sequence: number;
};

export async function fetchPolicyLines(signal?: AbortSignal): Promise<PolicyLine[]> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/policies/lines`, {
    method: "GET",
    headers: { Accept: "application/json" },
    cache: "no-store",
    signal,
  });
  if (!res.ok) {
    return handleErrorResponse(res);
  }
  const data = (await res.json()) as { lines: PolicyLine[] };
  const lines = data.lines || [];
  return lines
    .slice()
    .sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));
}

export async function addCedarPolicy(cedar: string, signal?: AbortSignal): Promise<PoliciesResponse> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/policies/add`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ cedar }),
    signal,
  });
  if (!res.ok) {
    return handleErrorResponse(res);
  }
  return (await res.json()) as PoliciesResponse;
}

export async function addPolicyFromAction(
  effect: "permit" | "forbid",
  action: { type: string; name: string },
  signal?: AbortSignal
): Promise<PoliciesResponse> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/policies/add-from-action`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ effect, action }),
    signal,
  });
  if (!res.ok) {
    return handleErrorResponse(res);
  }
  return (await res.json()) as PoliciesResponse;
}

export async function deletePolicyLine(
  payload: { id?: string; cedar?: string },
  signal?: AbortSignal
): Promise<PoliciesResponse> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/policies/delete`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
    signal,
  });
  if (!res.ok) {
    return handleErrorResponse(res);
  }
  return (await res.json()) as PoliciesResponse;
}

export function policiesToBlocks(response: PoliciesResponse): {
  blocksActive: PolicyBlock[];
  blocksRuntime: PolicyBlock[];
  blocksFile: PolicyBlock[];
  blocksRuntimeOnly: PolicyBlock[];
  blocksFileOnly: PolicyBlock[];
} {
  const cedarRuntime = response.cedarRuntime || "";
  const cedarFile = response.cedarFile || "";
  // Annotate blocks by layer with the corresponding Cedar source.
  const activeBlocks = layerToBlocks(response.active, "active", cedarRuntime || cedarFile);
  const runtimeBlocks = layerToBlocks(response.runtime, "runtime", cedarRuntime);
  const fileBlocks = layerToBlocks(response.file, "file", cedarFile);

  // Diff by ruleKey to derive runtime-only and file-only
  const fileKeys = new Set(fileBlocks.map(b => b.ruleKey));
  const runtimeKeys = new Set(runtimeBlocks.map(b => b.ruleKey));
  const runtimeOnly = runtimeBlocks.filter(b => !fileKeys.has(b.ruleKey));
  const fileOnly = fileBlocks.filter(b => !runtimeKeys.has(b.ruleKey));

  return {
    blocksActive: activeBlocks,
    blocksRuntime: runtimeBlocks,
    blocksFile: fileBlocks,
    blocksRuntimeOnly: runtimeOnly,
    blocksFileOnly: fileOnly,
  };
}

function ruleToBlock(rule: PolicyRuleView, id: string, cedar?: string, source?: PolicySource): PolicyBlock {
  const category = operationToCategory(rule.operation);
  const title = `${titleForOperation(rule.operation)} ${rule.target || rule.path || rule.hostname || "*"}`;
  const description = `${capitalize(rule.action)} ${friendlyOperation(rule.operation)} ${humanTarget(rule)}.`;
  const hash = hashString(rule.rule + id);

  return {
    id,
    title,
    description,
    category,
    effect: rule.action === "allow" ? "allow" : "deny",
    cedar: cedar || "",
    source,
    ruleKey: rule.rule,
    lastUpdated: Date.now(),
    instancesMatched: 1 + (hash % 5),
    activityScore: 40 + (hash % 60),
  };
}

function httpRuleToBlock(rule: HttpRuleView, id: string, cedar?: string, source?: PolicySource): PolicyBlock {
  const hash = hashString(rule.rule + id);
  return {
    id,
    title: `HTTP rewrite ${rule.host}`,
    description: `Rewrite ${rule.header} to \"${rule.value}\"`,
    category: "Networking",
    effect: "allow",
    cedar: cedar || "",
    source,
    ruleKey: rule.rule,
    lastUpdated: Date.now(),
    instancesMatched: 1 + (hash % 3),
    activityScore: 30 + (hash % 50),
  };
}

function layerToBlocks(layer: PolicyLayerView, source: PolicySource, cedar?: string): PolicyBlock[] {
  const blocks: PolicyBlock[] = [];
  layer.lsm.forEach((rule, idx) => {
    blocks.push(ruleToBlock(rule, `${source}-lsm-${idx}`, cedar, source));
  });
  layer.http.forEach((rule, idx) => {
    blocks.push(httpRuleToBlock(rule, `${source}-http-${idx}`, cedar, source));
  });
  return blocks;
}

function operationToCategory(op: string): PolicyCategory {
  if (op.startsWith("net.")) return "Networking";
  if (op.startsWith("file.")) return "Filesystem";
  if (op.startsWith("proc.")) return "Processes";
  return "Dependencies";
}

function friendlyOperation(op: string): string {
  if (op.startsWith("file.open")) return "file access to";
  if (op === "proc.exec") return "process execution of";
  if (op.startsWith("net.")) return "network access to";
  return op;
}

function titleForOperation(op: string): string {
  switch (op) {
    case "file.open":
      return "File access";
    case "file.open:ro":
      return "File read";
    case "file.open:rw":
      return "File write";
    case "proc.exec":
      return "Process exec";
    case "net.connect":
      return "Network connect";
    default:
      return op;
  }
}

function humanTarget(rule: PolicyRuleView): string {
  if (rule.hostname) {
    return rule.hostname;
  }
  if (rule.ip) {
    return rule.port ? `${rule.ip}:${rule.port}` : rule.ip;
  }
  if (rule.target) return rule.target;
  if (rule.path) return rule.path;
  return "the configured resource";
}

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function hashString(input: string): number {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 5) - hash + input.charCodeAt(i);
    hash |= 0; // Convert to 32bit integer
  }
  return Math.abs(hash);
}
