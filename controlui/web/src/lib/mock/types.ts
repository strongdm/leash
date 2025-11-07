export type InstanceStatus = "online" | "offline" | "starting" | "stopping";

export type Instance = {
  id: string;
  agent: string;
  platform: string;
  displayName?: string;
  lastCommand?: string;
  status: InstanceStatus;
  lastSeen: number; // epoch ms
};

export type ActionType =
  | "file/open"
  | "file/write"
  | "net/connect"
  | "proc/exec"
  | "fs/list"
  | "dns/resolve"
  | "mcp/deny"
  | "mcp/allow"
  | "mcp/list"
  | "mcp/call"
  | "mcp/resources"
  | "mcp/prompts"
  | "mcp/init"
  | "mcp/notify";

export type Action = {
  id: string;
  instanceId: string;
  type: ActionType;
  name: string;
  repeatCount?: number;
  ts: number; // epoch ms
  allowed: boolean;
  outcome?: string;
  method?: string;
  server?: string;
  tool?: string;
  status?: number;
  transport?: string;
  proto?: string;
  durationMs?: number;
  session?: string;
  notification?: boolean;
  requestId?: string;
  error?: string;
  secretHits?: string[];
};

export type SimulationState = {
  instances: Map<string, Instance>;
  recentActions: Action[]; // bounded window
  totals: {
    actionsLast60s: number[]; // 60 buckets (per second)
    deniedLast60s: number[]; // 60 buckets (per second)
    cursor: number; // index into ring buffers
  };
};
