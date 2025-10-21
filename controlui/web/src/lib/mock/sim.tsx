"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useState,
} from "react";
import { faker } from "@faker-js/faker";
import { Action, ActionType, Instance, SimulationState } from "./types";
import { id, now, pick } from "./random";
import type { PoliciesResponse, PolicyLine } from "@/lib/policy/api";

declare global {
  interface Window {
    __leashRefreshTitle?: () => void;
  }
}

const TICK_MS = 700;
const HEARTBEAT_MS = 1_000;
const OFFLINE_THRESHOLD_MS = 60_000;
const MAX_RECENT = 25000;

const AGENTS = ["Claude Code", "Codex", "Cursor", "Other"] as const;
const PLATFORMS = ["macOS", "Linux", "Windows", "k8s"] as const;
const ACTION_TYPES: ActionType[] = [
  "file/open",
  "file/write",
  "net/connect",
  "proc/exec",
  "fs/list",
  "dns/resolve",
  "mcp/call",
  "mcp/list",
  "mcp/resources",
  "mcp/prompts",
  "mcp/notify",
  "mcp/init",
  "mcp/allow",
  "mcp/deny",
];

type MCPScenario = {
  server: string;
  tool: string;
  calls: string[];
  lists?: string[];
  resources?: string[];
  prompts?: string[];
  notifications?: string[];
  sessions?: string[];
  transports?: readonly string[];
  protocols?: readonly string[];
  allowName: string;
  denyName: string;
};

const MCP_SCENARIOS: MCPScenario[] = [
  {
    server: "mcp.context7.control",
    tool: "context7.workflow",
    calls: [
      "context7.runWorkflow",
      "context7.syncKnowledgeBase",
      "context7.scheduleTask",
    ],
    notifications: ["context7.alert.updated", "context7.job.completed"],
    sessions: ["context7.session"],
    resources: ["context7.datasets", "context7.runs"],
    prompts: ["context7.operator.assist"],
    allowName: "context7 policy allow",
    denyName: "context7 policy deny",
  },
  {
    server: "api.notion.com",
    tool: "notion.pages",
    calls: [
      "notion.pages.read",
      "notion.pages.update",
      "notion.database.query",
    ],
    notifications: ["notion.changefeed"],
    resources: ["notion.databases", "notion.pages"],
    prompts: ["notion.summary"],
    sessions: ["notion.workspace"],
    allowName: "notion allow edit",
    denyName: "notion deny export",
  },
  {
    server: "api.github.com",
    tool: "github.repo",
    calls: [
      "github.repos.pull",
      "github.repos.push",
      "github.repos.merge",
    ],
    notifications: ["github.pr.review", "github.deployment.status"],
    resources: ["github.repos", "github.branches"],
    prompts: ["github.commit.message"],
    sessions: ["github.session"],
    allowName: "github allow push",
    denyName: "github deny force-push",
  },
  {
    server: "aurora.prod.internal",
    tool: "database.sql",
    calls: [
      "database.connection.open",
      "database.query.select",
      "database.transaction.write",
    ],
    notifications: ["database.replica.lag"],
    resources: ["database.schemas", "database.tables"],
    prompts: ["database.optimizer"],
    sessions: ["database.session"],
    allowName: "database allow write",
    denyName: "database deny drop-table",
  },
  {
    server: "ec2.amazonaws.com",
    tool: "aws.ec2",
    calls: [
      "aws.ec2.createInstance",
      "aws.ec2.terminateInstance",
      "aws.ec2.describeInstances",
    ],
    notifications: ["aws.ec2.state-change"],
    resources: ["aws.ec2.instances"],
    prompts: ["aws.ec2.advisor"],
    sessions: ["aws.account"],
    allowName: "aws allow instance",
    denyName: "aws deny instance-deletion",
  },
  {
    server: "s3.amazonaws.com",
    tool: "aws.s3",
    calls: [
      "aws.s3.getObject",
      "aws.s3.putObject",
      "aws.s3.deleteObject",
    ],
    notifications: ["aws.s3.object-created"],
    resources: ["aws.s3.buckets"],
    prompts: ["aws.s3.optimizer"],
    sessions: ["aws.account"],
    allowName: "aws allow s3-write",
    denyName: "aws deny s3-delete",
  },
  {
    server: "compute.googleapis.com",
    tool: "gcp.compute",
    calls: [
      "gcp.compute.instances.insert",
      "gcp.compute.instances.delete",
      "gcp.compute.instances.get",
    ],
    notifications: ["gcp.compute.instance-status"],
    resources: ["gcp.compute.instances"],
    prompts: ["gcp.compute.assistant"],
    sessions: ["gcp.project"],
    allowName: "gcp allow instance",
    denyName: "gcp deny instance-delete",
  },
  {
    server: "storage.googleapis.com",
    tool: "gcp.storage",
    calls: [
      "gcp.storage.objects.get",
      "gcp.storage.objects.insert",
      "gcp.storage.objects.delete",
    ],
    notifications: ["gcp.storage.object-event"],
    resources: ["gcp.storage.buckets"],
    prompts: ["gcp.storage.optimizer"],
    sessions: ["gcp.project"],
    allowName: "gcp allow storage-write",
    denyName: "gcp deny storage-delete",
  },
];

const MCP_TRANSPORTS = ["https", "grpc", "websocket"] as const;
const MCP_PROTOCOLS = ["http/2", "http/1.1", "grpc", "ws-json"] as const;
const MCP_OUTCOMES = ["timeout", "forbidden", "error", "cancelled"];

type DataMode = "sim" | "live";
type ConnectionStatus = "idle" | "connecting" | "ready" | "error";

type IngestPayload = {
  instance: Instance;
  action?: Action;
  raw: WebsocketLogEntry;
};

type PolicySnapshotPayload = {
  policies: PoliciesResponse;
  lines?: PolicyLine[];
};

export type ActionKind =
  | { type: "tick"; ts: number }
  | { type: "spawn-instance"; inst: Instance }
  | { type: "retire-instance"; id: string; ts: number }
  | { type: "emit-action"; action: Action }
  | { type: "reset"; ts?: number }
  | { type: "heartbeat"; ts: number }
  | { type: "ingest"; payload: IngestPayload };

type WebsocketLogEntry = {
  time?: string;
  event?: string;
  pid?: number;
  cgroup?: number;
  exe?: string;
  path?: string;
  decision?: string;
  protocol?: string;
  addr?: string;
  status?: number;
  error?: string;
  args?: string;
  argc?: number;
  hostname?: string;
  header?: string;
  old_value?: string;
  new_value?: string;
  auth?: string;
  instance_id?: string;
  seq?: number;
  started_at?: string;
  uptime_s?: number;
  last_seq?: number;
  // MCP fields
  rule?: string;
  method?: string;
  server?: string;
  tool?: string;
  // Additional MCP/transport metadata parsed from logfmt/WebSocket payloads
  outcome?: string;
  transport?: string;
  proto?: string;
  duration_ms?: number;
  session?: string;
  notification?: boolean;
  id?: string; // request id
  payload?: unknown;
};

function makeInitialInstances(n = 8): Instance[] {
  return Array.from({ length: n }).map(() => newInstance());
}

function newInstance(): Instance {
  const agent = pick(AGENTS);
  const platform = pick(PLATFORMS);
  return {
    id: id("inst"),
    agent,
    platform,
    displayName: `${agent} ${Math.random().toString(36).slice(-4)}`,
    lastCommand: undefined,
    status: "online",
    lastSeen: now(),
  };
}

function randomAction(inst: Instance, ts: number): Action {
  const baseType = pick(ACTION_TYPES);
  const type = (() => {
    if (!baseType.startsWith("mcp/")) {
      return baseType;
    }
    if (Math.random() > 0.25) {
      return pick(ACTION_TYPES.filter((t) => !t.startsWith("mcp/")));
    }
    return baseType;
  })();
  let allowed = Math.random() > 0.12;
  if (type === "mcp/deny") allowed = false;
  if (type === "mcp/allow") allowed = true;
  if (type === "mcp/notify" || type === "mcp/init" || type === "mcp/list" || type === "mcp/resources" || type === "mcp/prompts") {
    allowed = true;
  }

  const action: Action = {
    id: id("act"),
    instanceId: inst.id,
    type,
    name: "unknown",
    ts,
    allowed,
  };

  switch (type) {
    case "file/open":
      action.name = faker.system.fileName();
      break;
    case "file/write":
      action.name = faker.system.filePath();
      break;
    case "net/connect":
      action.name = faker.internet.url({ protocol: "https" });
      break;
    case "proc/exec":
      action.name = faker.system.fileName();
      break;
    case "fs/list":
      action.name = faker.system.directoryPath();
      break;
    case "dns/resolve":
      action.name = faker.internet.domainName();
      break;
    default: {
      if (type.startsWith("mcp/")) {
        const scenario = pick(MCP_SCENARIOS);
        const server = scenario.server;
        const tool = scenario.tool;
        const durationMs = 30 + Math.floor(Math.random() * 450);
        const status = allowed ? pick([200, 201, 202, 204]) : pick([400, 401, 403, 409, 429, 500]);
        action.server = server;
        action.tool = tool;
        action.transport = pick(scenario.transports ?? MCP_TRANSPORTS);
        action.proto = pick(scenario.protocols ?? MCP_PROTOCOLS);
        action.durationMs = durationMs;
        action.status = status;
        action.session = `sess-${Math.random().toString(36).slice(-6)}`;
        action.requestId = id("req");
        action.outcome = allowed ? "success" : pick(MCP_OUTCOMES);

        if (!allowed) {
          action.allowed = false;
        }

        switch (type) {
        case "mcp/call": {
          const callName = pick(scenario.calls);
          action.name = callName;
          action.method = "tools.call";
          break;
        }
        case "mcp/list": {
          const listName = pick(scenario.lists ?? [`${scenario.tool}.list`]);
          action.name = listName;
          action.method = "tools.list";
          break;
        }
        case "mcp/resources": {
          const resourceName = pick(scenario.resources ?? [`${scenario.tool}.resources`]);
          action.name = resourceName;
          action.method = "resources.list";
          break;
        }
        case "mcp/prompts": {
          const promptName = pick(scenario.prompts ?? [`${scenario.tool}.prompts`]);
          action.name = promptName;
          action.method = "prompts.list";
          break;
        }
        case "mcp/notify": {
          action.notification = true;
          const note = pick(scenario.notifications ?? ["notification"]);
          action.name = note;
          action.method = "notifications.push";
          action.status = 200;
          action.outcome = "success";
          break;
        }
        case "mcp/init": {
          action.method = "session.init";
          action.name = pick(scenario.sessions ?? ["session.init"]);
          action.status = 200;
          action.outcome = "success";
          break;
        }
        case "mcp/allow": {
          action.method = "policy.enforcement";
          action.name = scenario.allowName;
          action.status = 200;
          action.outcome = "success";
          allowed = true;
          break;
        }
        case "mcp/deny": {
          action.method = "policy.enforcement";
          action.name = scenario.denyName;
          action.status = pick([403, 429]);
          action.outcome = pick(["forbidden", "denied"]);
          allowed = false;
          break;
        }
        default:
          action.name = `${scenario.tool}@${scenario.server}`;
          action.method = "tools.call";
        }
      }
    }
  }

  action.allowed = allowed;
  return action;
}

function emptyState(ts?: number): SimulationState {
  const baseTs = typeof ts === "number" ? ts : now();
  const cursor = Math.floor(baseTs / 1000) % 60;
  return {
    instances: new Map<string, Instance>(),
    recentActions: [],
    totals: {
      actionsLast60s: Array.from({ length: 60 }).map(() => 0),
      deniedLast60s: Array.from({ length: 60 }).map(() => 0),
      cursor,
    },
  };
}

function rotateTotals(totals: SimulationState["totals"], ts: number) {
  const cursor = Math.floor(ts / 1000) % 60;
  const actionsLast60s = totals.actionsLast60s.slice();
  const deniedLast60s = totals.deniedLast60s.slice();

  if (cursor !== totals.cursor) {
    let steps = (cursor - totals.cursor + 60) % 60;
    if (steps === 0) steps = 60;
    for (let i = 1; i <= steps; i++) {
      const index = (totals.cursor + i) % 60;
      actionsLast60s[index] = 0;
      deniedLast60s[index] = 0;
    }
  }

  return { actionsLast60s, deniedLast60s, cursor };
}

function bumpTotals(
  totals: SimulationState["totals"],
  ts: number,
  actionsCount: number,
  deniedCount: number,
) {
  const rotated = rotateTotals(totals, ts);
  rotated.actionsLast60s[rotated.cursor] += actionsCount;
  rotated.deniedLast60s[rotated.cursor] += deniedCount;
  return rotated;
}

function mergeInstance(existing: Instance | undefined, incoming: Instance): Instance {
  if (!existing) return incoming;
  return {
    ...existing,
    ...incoming,
    agent: preferValue(existing.agent, incoming.agent) ?? existing.agent,
    platform: preferValue(existing.platform, incoming.platform) ?? existing.platform,
    displayName: preferValue(existing.displayName, incoming.displayName) ?? existing.displayName,
    lastCommand: incoming.lastCommand ?? existing.lastCommand,
  };
}

function preferValue(current?: string, next?: string) {
  const empty = (v?: string) => !v || v === "unknown";
  if (empty(next)) return current;
  if (empty(current)) return next;
  return current ?? next;
}

export function reducer(state: SimulationState, action: ActionKind): SimulationState {
  switch (action.type) {
    case "tick": {
      const instances = new Map(state.instances);
      const spawn = Math.random() < 0.08;
      const retire = !spawn && instances.size > 4 && Math.random() < 0.04;

      if (spawn) {
        const inst = newInstance();
        instances.set(inst.id, inst);
      } else if (retire) {
        const victim = pick([...instances.keys()]);
        const inst = instances.get(victim);
        if (inst) instances.set(victim, { ...inst, status: "offline", lastSeen: action.ts });
      }

      const online = [...instances.values()].filter((i) => i.status === "online");
      let recent = state.recentActions.slice();
      let actionsCount = 0;
      let deniedCount = 0;

      online.forEach((inst) => {
        const k = Math.random() < 0.5 ? 0 : Math.random() < 0.7 ? 1 : 2;
        if (k > 0) instances.set(inst.id, { ...inst, lastSeen: action.ts });
        for (let i = 0; i < k; i++) {
          const act = randomAction(inst, action.ts + i);
          recent.push(act);
          actionsCount++;
          if (!act.allowed) deniedCount++;
        }
      });
      if (recent.length > MAX_RECENT) recent = recent.slice(-MAX_RECENT);

      // keep historical instances so detail pages remain informative; just mark offline via heartbeat

      const totals = bumpTotals(state.totals, action.ts, actionsCount, deniedCount);

      return {
        instances,
        recentActions: recent,
        totals,
      };
    }
    case "spawn-instance": {
      const instances = new Map(state.instances);
      instances.set(action.inst.id, action.inst);
      return { ...state, instances };
    }
    case "retire-instance": {
      const instances = new Map(state.instances);
      const inst = instances.get(action.id);
      if (inst) instances.set(action.id, { ...inst, status: "offline", lastSeen: action.ts });
      return { ...state, instances };
    }
    case "emit-action": {
      const recent = [...state.recentActions, action.action].slice(-MAX_RECENT);
      const totals = bumpTotals(state.totals, action.action.ts, 1, action.action.allowed ? 0 : 1);
      return { ...state, recentActions: recent, totals };
    }
    case "reset": {
      return emptyState(action.ts);
    }
    case "heartbeat": {
      const ts = action.ts;
      const instances = new Map(state.instances);
      for (const [key, inst] of instances) {
        const age = ts - inst.lastSeen;
        const shouldBeOnline = age <= OFFLINE_THRESHOLD_MS;
        if (shouldBeOnline && inst.status !== "online") {
          instances.set(key, { ...inst, status: "online" });
        } else if (!shouldBeOnline && inst.status !== "offline") {
          instances.set(key, { ...inst, status: "offline" });
        }
      }
      const totals = rotateTotals(state.totals, ts);
      return {
        instances,
        recentActions: state.recentActions.slice(-MAX_RECENT),
        totals,
      };
    }
	case "ingest": {
		const { action: act, instance } = action.payload;
		const instances = new Map(state.instances);
		const merged = mergeInstance(instances.get(instance.id), instance);
		const lastSeen = act ? act.ts : instance.lastSeen;
		instances.set(instance.id, { ...merged, status: "online", lastSeen });
		if (!act) {
			return {
				instances,
				recentActions: state.recentActions.slice(-MAX_RECENT),
				totals: state.totals,
			};
		}
		const recent = state.recentActions.slice();
		const key = repeatKey(act);
		const existingIndex = recent.findIndex((item) => repeatKey(item) === key);
		let nextAction: Action;
		if (existingIndex >= 0) {
			const existing = recent[existingIndex];
			const repeatCount = (existing.repeatCount ?? 1) + 1;
			nextAction = { ...act, repeatCount };
			recent.splice(existingIndex, 1);
		} else {
			nextAction = { ...act, repeatCount: 1 };
		}
		recent.push(nextAction);
		const bounded = recent.slice(-MAX_RECENT);
		const totals = bumpTotals(state.totals, act.ts, 1, act.allowed ? 0 : 1);
		return {
			instances,
			recentActions: bounded,
			totals,
		};
	}
  }
}

class IdentityRegistry {
  private counter = 0;
  private byCgroup = new Map<number, string>();
  private byPid = new Map<number, string>();
  private byAddr = new Map<string, string>();
  private byHostname = new Map<string, string>();
  private lastResolved: string | null = null;

  reset() {
    this.counter = 0;
    this.byCgroup.clear();
    this.byPid.clear();
    this.byAddr.clear();
    this.byHostname.clear();
    this.lastResolved = null;
  }

  resolveId(entry: WebsocketLogEntry): string {
    if (typeof entry.cgroup === "number") {
      const existing = this.byCgroup.get(entry.cgroup);
      if (existing) {
        this.register(existing, entry);
        return existing;
      }
      const idValue = `l-${entry.cgroup}`;
      this.register(idValue, entry);
      return idValue;
    }

    if (typeof entry.pid === "number") {
      const existing = this.byPid.get(entry.pid);
      if (existing) {
        this.register(existing, entry);
        return existing;
      }
    }

    if (entry.addr) {
      const existing = this.byAddr.get(entry.addr);
      if (existing) {
        this.register(existing, entry);
        return existing;
      }
    }

    if (entry.hostname) {
      const existing = this.byHostname.get(entry.hostname);
      if (existing) {
        this.register(existing, entry);
        return existing;
      }
    }

    if (this.lastResolved) {
      this.register(this.lastResolved, entry);
      return this.lastResolved;
    }

    const generated = `ghost-${++this.counter}`;
    this.register(generated, entry);
    return generated;
  }

  private register(idValue: string, entry: WebsocketLogEntry) {
    if (typeof entry.cgroup === "number") this.byCgroup.set(entry.cgroup, idValue);
    if (typeof entry.pid === "number") this.byPid.set(entry.pid, idValue);
    if (entry.addr) this.byAddr.set(entry.addr, idValue);
    if (entry.hostname) this.byHostname.set(entry.hostname, idValue);
    if (typeof entry.cgroup === "number" || typeof entry.pid === "number") {
      this.lastResolved = idValue;
    } else if (!this.lastResolved) {
      this.lastResolved = idValue;
    }
  }

  assign(idValue: string, entry: WebsocketLogEntry) {
    this.register(idValue, entry);
  }
}

const identityRegistry = new IdentityRegistry();

function repeatKey(action: Action) {
  return [
    action.instanceId ?? "",
    action.type,
    action.name,
    action.allowed ? "allow" : "deny",
    action.tool ?? "",
    action.server ?? "",
    action.method ?? "",
    typeof action.status === "number" ? String(action.status) : "",
    action.transport ?? "",
    action.proto ?? "",
  ].join("|");
}

const SimulationCtx = createContext<{
  state: SimulationState;
  mode: DataMode;
  setMode: (mode: DataMode) => void;
  status: ConnectionStatus;
  error: string | null;
  wsUrl: string | null;
  latestPolicySnapshot: PolicySnapshotPayload | null;
  connectionVersion: number;
} | null>(null);

export function SimulationProvider({ children, initialMode = "sim", persist = true }: { children: React.ReactNode; initialMode?: DataMode; persist?: boolean }) {
  const [state, dispatch] = useReducer(reducer, undefined, () => emptyState(now()));
  const [modeState, setModeState] = useState<DataMode>(initialMode);
  const [status, setStatus] = useState<ConnectionStatus>("ready");
  const [error, setError] = useState<string | null>(null);
  const [wsUrl, setWsUrl] = useState<string | null>(() => process.env.NEXT_PUBLIC_LEASH_WS_URL ?? null);
  const [latestPolicySnapshot, setLatestPolicySnapshot] = useState<PolicySnapshotPayload | null>(null);
  const [connectionVersion, setConnectionVersion] = useState(0);

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (!persist) {
      // Respect the provided initialMode without touching localStorage
      setStatus(initialMode === "live" ? "connecting" : "ready");
      return;
    }
    const stored = window.localStorage.getItem("leash:data-source");
    if (stored === "sim" || stored === "live") {
      setModeState(stored);
      setStatus(stored === "live" ? "connecting" : "ready");
    } else if (process.env.NEXT_PUBLIC_DEFAULT_DATA_MODE === "live") {
      setModeState("live");
      setStatus("connecting");
    }
  }, [initialMode, persist]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (!persist) return;
    window.localStorage.setItem("leash:data-source", modeState);
  }, [modeState, persist]);

  useEffect(() => {
    if (wsUrl || typeof window === "undefined") return;
    // Prefer current origin (host:port) so the WS follows port hops automatically.
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const hostPort = window.location.host || (window.location.hostname || "localhost");
    setWsUrl(`${protocol}://${hostPort}/api`);
  }, [wsUrl]);

  const setMode = useCallback(
    (nextMode: DataMode) => {
      setModeState((prev) => {
        if (prev === nextMode) return prev;
        setStatus(nextMode === "live" ? "connecting" : "ready");
        setError(null);
        return nextMode;
      });
    },
    [],
  );

  useEffect(() => {
    if (modeState !== "sim") return;

    dispatch({ type: "reset", ts: now() });
    identityRegistry.reset();
    setLatestPolicySnapshot(null);
    setStatus("ready");
    setError(null);

    makeInitialInstances().forEach((inst) => dispatch({ type: "spawn-instance", inst }));
    const interval = window.setInterval(() => dispatch({ type: "tick", ts: now() }), TICK_MS);

    return () => {
      window.clearInterval(interval);
    };
  }, [modeState, dispatch]);

  useEffect(() => {
    if (modeState !== "live") return;
    if (!wsUrl) return;

    dispatch({ type: "reset", ts: now() });
    identityRegistry.reset();
    setLatestPolicySnapshot(null);
    setError(null);

    let cancelled = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let attempts = 0;

    const scheduleReconnect = () => {
      if (cancelled) return;
      attempts += 1;
      const delay = Math.min(1_000 * attempts, 5_000);
      reconnectTimer = window.setTimeout(connect, delay);
    };

    const clearLiveState = (ts?: number) => {
      dispatch({ type: "reset", ts: ts ?? now() });
      identityRegistry.reset();
      setLatestPolicySnapshot(null);
    };

    const connect = () => {
      if (cancelled) return;
      setStatus("connecting");
      try {
        socket = new WebSocket(wsUrl);
      } catch (err) {
        setStatus("error");
        setError(err instanceof Error ? err.message : "Failed to create WebSocket");
        scheduleReconnect();
        return;
      }

      socket.onopen = () => {
        if (cancelled) return;
        clearLiveState(now());
        setStatus("ready");
        setError(null);
        attempts = 0;
        setConnectionVersion((v) => v + 1);
      };

      socket.onmessage = (event) => {
        if (cancelled) return;
        const entries = parseWebsocketEntries(event.data);
        if (entries.length === 0) return;
        entries.forEach((entry) => {
          if (entry.event === "policy.snapshot") {
            const snapshot = parsePolicySnapshot(entry.payload);
            if (snapshot) {
              setLatestPolicySnapshot(snapshot);
            }
            return;
          }
          const payload = transformLogEntry(entry);
          if (payload) {
            dispatch({ type: "ingest", payload });
          }
        });
      };

      socket.onerror = () => {
        if (cancelled) return;
        setStatus("error");
        setError("WebSocket error");
      };

      socket.onclose = () => {
        if (cancelled) return;
        setStatus("error");
        setError((prev) => prev ?? "WebSocket closed");
        scheduleReconnect();
      };
    };

    const heartbeatTimer = window.setInterval(() => {
      dispatch({ type: "heartbeat", ts: now() });
    }, HEARTBEAT_MS);

    connect();

    return () => {
      cancelled = true;
      if (heartbeatTimer) window.clearInterval(heartbeatTimer);
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      if (socket) {
        try {
          socket.close();
        } catch (err) {
          console.warn("WebSocket close error", err);
        }
      }
    };
  }, [modeState, wsUrl, dispatch]);

  const value = useMemo(
    () => ({
      state,
      mode: modeState,
      setMode,
      status,
      error,
      wsUrl,
      latestPolicySnapshot,
      connectionVersion,
    }),
    [state, modeState, setMode, status, error, wsUrl, latestPolicySnapshot, connectionVersion],
  );

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (status !== "ready") return;
    const refresh = window.__leashRefreshTitle;
    if (typeof refresh === "function") {
      refresh();
    }
  }, [status, connectionVersion]);

  return <SimulationCtx.Provider value={value}>{children}</SimulationCtx.Provider>;
}

export function useSimulation() {
  const ctx = useContext(SimulationCtx);
  if (!ctx) throw new Error("useSimulation must be used within SimulationProvider");
  return ctx.state;
}

export function useDataSource() {
  const ctx = useContext(SimulationCtx);
  if (!ctx) throw new Error("useDataSource must be used within SimulationProvider");
  return {
    mode: ctx.mode,
    setMode: ctx.setMode,
    status: ctx.status,
    error: ctx.error,
    wsUrl: ctx.wsUrl,
    connectionVersion: ctx.connectionVersion,
  };
}

export function useLatestPolicySnapshot() {
  const ctx = useContext(SimulationCtx);
  if (!ctx) throw new Error("useLatestPolicySnapshot must be used within SimulationProvider");
  return ctx.latestPolicySnapshot;
}

export function actionsPerMinute(state: SimulationState) {
  return state.totals.actionsLast60s.reduce((a, b) => a + b, 0);
}

export function deniedPerMinute(state: SimulationState) {
  return state.totals.deniedLast60s.reduce((a, b) => a + b, 0);
}

function parseWebsocketEntries(raw: string): WebsocketLogEntry[] {
  if (typeof raw !== "string") {
    console.warn("[Leash] Unexpected websocket payload type", typeof raw);
    return [];
  }

  if (!raw.trim()) return [];

  const parts = raw.includes("\n") ? raw.split(/\r?\n/) : [raw];
  const entries: WebsocketLogEntry[] = [];

  parts.forEach((part) => {
    const trimmed = part.trim();
    if (!trimmed) return;
    try {
      const entry = JSON.parse(trimmed) as WebsocketLogEntry;
      entries.push(entry);
    } catch (err) {
      console.warn("[Leash] Failed to parse websocket message", err, trimmed);
    }
  });

  return entries;
}

function parsePolicySnapshot(payload: unknown): PolicySnapshotPayload | null {
  if (!payload || typeof payload !== "object") {
    return null;
  }
  const record = payload as Record<string, unknown>;
  const policies = record.policies;
  if (!policies || typeof policies !== "object") {
    return null;
  }
  let lines: PolicyLine[] | undefined;
  if (Array.isArray(record.lines)) {
    lines = record.lines as PolicyLine[];
  }
  return {
    policies: policies as PoliciesResponse,
    lines,
  };
}

function transformLogEntry(entry: WebsocketLogEntry): IngestPayload | null {
  if (!entry.event) {
    logDroppedEvent("missing event", entry);
    return null;
  }
  if (entry.event === "policy.snapshot") {
    return null;
  }

  const tsRaw = entry.time ? Date.parse(entry.time) : now();
  const ts = Number.isNaN(tsRaw) ? now() : tsRaw;

  let allowed: boolean;
  if (typeof entry.decision === "string") {
    allowed = entry.decision.toLowerCase() !== "denied";
  } else if (entry.event?.endsWith(".deny")) {
    allowed = false;
  } else if (entry.event?.endsWith(".allow")) {
    allowed = true;
  } else {
    allowed = true;
  }
  if (entry.outcome && entry.outcome.toLowerCase() === "error") {
    allowed = false;
  }

  let instanceId: string;
  if (entry.instance_id) {
    instanceId = entry.instance_id;
    identityRegistry.assign(instanceId, entry);
  } else {
    instanceId = identityRegistry.resolveId(entry);
  }
  const instance: Instance = {
    id: instanceId,
    agent: deriveAgent(entry),
    platform: derivePlatform(entry),
    displayName: deriveDisplayName(entry),
    lastCommand: deriveLastCommand(entry),
    status: "online",
    lastSeen: ts,
  };

  if (entry.event === "leash.hello" || entry.event === "leash.heartbeat") {
    return { instance, raw: entry };
  }

  let type: ActionType;
  let name: string;

  switch (entry.event) {
    case "file.open":
    case "file.open:ro":
      type = "file/open";
      name = entry.path ?? entry.exe ?? "file.open";
      break;
    case "file.open:rw":
      type = "file/write";
      name = entry.path ?? entry.exe ?? "file.open:rw";
      break;
    case "proc.exec":
      type = "proc/exec";
      name = buildExecName(entry);
      break;
    case "net.send":
      type = "net/connect";
      name = buildNetName(entry);
      break;
case "dns.query":
      type = "dns/resolve";
      name = buildDNSName(entry);
      break;
    case "http.request":
      type = "net/connect";
      name = buildHttpRequestName(entry);
      break;
    case "http.rewrite":
      type = "net/connect";
      name = buildHttpRewriteName(entry);
      break;
    case "mcp.deny":
      type = "mcp/deny";
      name = buildMcpName(entry, "mcp.deny");
      break;
    case "mcp.allow":
      type = "mcp/allow";
      name = buildMcpName(entry, "mcp.allow");
      break;
    case "mcp.discover":
      type = "mcp/list";
      name = buildMcpActivityName(entry);
      break;
    case "mcp.call":
      type = "mcp/call";
      name = buildMcpActivityName(entry);
      break;
    case "mcp.resources.list":
    case "mcp.resources.read":
      type = "mcp/resources";
      name = buildMcpActivityName(entry);
      break;
    case "mcp.prompts.list":
    case "mcp.prompts.get":
      type = "mcp/prompts";
      name = buildMcpActivityName(entry);
      break;
    case "mcp.initialize":
    case "mcp.initialized":
      type = "mcp/init";
      name = buildMcpActivityName(entry);
      break;
    case "mcp.notification":
      type = "mcp/notify";
      name = buildMcpActivityName(entry);
      break;
    default:
      logDroppedEvent(`unsupported event '${entry.event}'`, entry);
      return null;
  }

  if (type.endsWith("/deny")) {
    allowed = false;
  } else if (type.endsWith("/allow")) {
    allowed = true;
  }

  const action: Action = {
    id: id("evt"),
    instanceId: instance.id,
    type,
    name,
    ts,
    allowed,
    outcome: entry.outcome,
    method: entry.method,
    server: entry.server,
    tool: entry.tool,
    status: entry.status,
    transport: entry.transport ?? entry.protocol,
    proto: entry.proto,
    durationMs: entry.duration_ms,
    session: entry.session,
    notification: entry.notification ?? (entry.event === "mcp.notification"),
    requestId: entry.id,
    error: entry.error,
  };

  return { instance, action, raw: entry };
}

function deriveAgent(entry: WebsocketLogEntry): string {
  if (entry.exe) return entry.exe;
  if (entry.hostname) return entry.hostname;
  return "Other";
}

function derivePlatform(entry: WebsocketLogEntry): string {
  if (entry.hostname) return entry.hostname;
  if (entry.protocol) return entry.protocol.toUpperCase();
  return "Linux";
}

function buildExecName(entry: WebsocketLogEntry): string {
  const base = entry.path ?? entry.exe ?? "exec";
  if (entry.args) {
    return `${base} ${entry.args}`.trim();
  }
  return base;
}

function buildNetName(entry: WebsocketLogEntry): string {
  const host = entry.hostname ?? entry.addr ?? "network";
  const protocol = entry.protocol ? entry.protocol.toUpperCase() : undefined;
  const status = typeof entry.status === "number" ? ` [${entry.status}]` : "";
  const error = entry.error ? ` !${entry.error}` : "";
  return `${protocol ? `${protocol} ` : ""}${host}${status}${error}`.trim();
}

function buildDNSName(entry: WebsocketLogEntry): string {
  const question = entry.hostname ?? entry.addr ?? "dns.query";
  const answer = entry.addr ?? entry.hostname ?? "";
  if (question === answer || !answer) {
    return question;
  }
  return `${question} → ${answer}`;
}

function buildHttpRequestName(entry: WebsocketLogEntry): string {
  const addr = entry.addr ?? "http";
  const path = entry.path ?? "/";
  const status = typeof entry.status === "number" ? ` [${entry.status}]` : "";
  return `${addr} ${path}${status}`.trim();
}

function buildHttpRewriteName(entry: WebsocketLogEntry): string {
  const header = entry.header ?? "header";
  const from = entry.old_value ?? "";
  const to = entry.new_value ?? "";
  const auth = entry.auth ? ` (${entry.auth})` : "";
  if (from && to) return `${header}: ${from} -> ${to}${auth}`;
  if (to) return `${header}: ${to}${auth}`;
  if (from) return `${header}: ${from}${auth}`;
  return `${header}${auth}`.trim();
}

function buildMcpName(entry: WebsocketLogEntry, kind: "mcp.deny" | "mcp.allow" = "mcp.deny"): string {
  if (entry.rule) return entry.rule;
  const base = kind;
  const fragments = [
    entry.method ? `method=${entry.method}` : undefined,
    entry.server ? `server=${entry.server}` : undefined,
    entry.tool ? `tool=${entry.tool}` : undefined,
  ].filter(Boolean);
  const error = entry.error ? ` !${entry.error}` : "";
  return `${base}${fragments.length ? ` ${fragments.join(" ")}` : ""}${error}`.trim();
}

function buildMcpActivityName(entry: WebsocketLogEntry): string {
  const fragments: string[] = [];
  if (entry.method) fragments.push(entry.method);
  else if (entry.event) fragments.push(entry.event.replace("mcp.", "mcp"));
  if (entry.tool) fragments.push(`tool=${entry.tool}`);
  if (entry.server) fragments.push(`server=${entry.server}`);
  if (typeof entry.status === "number") fragments.push(`[${entry.status}]`);
  if (entry.transport) fragments.push(`via ${entry.transport}`);
  if (entry.session) fragments.push(`session=${entry.session}`);
  if (entry.outcome && entry.outcome !== "success") fragments.push(`!${entry.outcome}`);
  return fragments.length ? fragments.join(" ") : entry.event ?? "mcp";
}

function logDroppedEvent(reason: string, entry: WebsocketLogEntry) {
  if (typeof console === "undefined") return;
  if (process.env.NODE_ENV === "production") return;
  console.warn(`[Leash] Dropped websocket event (${reason})`, entry);
}

function deriveDisplayName(entry: WebsocketLogEntry): string {
  const raw = entry.exe ?? entry.hostname ?? entry.addr ?? entry.path ?? entry.event ?? "unknown";
  return raw.trim().replace(/\s+/g, " ") || "unknown";
}

function deriveLastCommand(entry: WebsocketLogEntry): string | undefined {
  switch (entry.event) {
    case "proc.exec":
      return entry.path ?? entry.exe ?? entry.args ?? "proc.exec";
    case "file.open":
    case "file.open:ro":
    case "file.open:rw":
      return entry.path ?? entry.exe ?? "file.open";
    case "net.send":
      return entry.addr ?? entry.hostname ?? "net.send";
    case "http.request":
      return `${entry.addr ?? "http"} ${entry.path ?? "/"}`.trim();
    case "http.rewrite":
      return entry.header ? `rewrite ${entry.header}` : "http.rewrite";
    case "leash.hello":
    case "leash.heartbeat":
      return undefined;
    default:
      return entry.event;
  }
}
