"use client";

import { useMemo, useState, useCallback, useEffect, memo, useRef } from "react";
import { useSimulation } from "@/lib/mock/sim";
import type { Action, ActionType } from "@/lib/mock/types";
import { timeAgo } from "@/lib/time";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Network, FileText, Terminal, List, Globe, Shield, Clock, Database, MessageSquare, Bell, Power, Check, X, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";

const typeIcon: Record<ActionType, React.ReactNode> = {
  "file/open": <FileText className="size-3" />,
  "file/write": <FileText className="size-3" />,
  "proc/exec": <Terminal className="size-3" />,
  "net/connect": <Network className="size-3" />,
  "fs/list": <List className="size-3" />,
  "dns/resolve": <Globe className="size-3" />,
  "mcp/deny": <Shield className="size-3" />,
  "mcp/allow": <Shield className="size-3" />,
  "mcp/list": <List className="size-3" />,
  "mcp/call": <Terminal className="size-3" />,
  "mcp/resources": <Database className="size-3" />,
  "mcp/prompts": <MessageSquare className="size-3" />,
  "mcp/init": <Power className="size-3" />,
  "mcp/notify": <Bell className="size-3" />,
};

const typeIconFor = (value: ActionType): React.ReactNode => typeIcon[value] ?? <List className="size-3" />;

const MIN_EVENTS_PANE_HEIGHT = 650;
const VIEWPORT_GUTTER_PX = 24;
const PROJECT_FALLBACK_SLUG = "project";

function slugifyForFilename(value: string): string {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || PROJECT_FALLBACK_SLUG;
}

function extractProjectFromTitle(raw: string): string | null {
  const pipeIndex = raw.indexOf("|");
  if (pipeIndex === -1) {
    return null;
  }
  const afterPipe = raw.slice(pipeIndex + 1);
  const gtIndex = afterPipe.indexOf(">");
  const projectSegment = (gtIndex === -1 ? afterPipe : afterPipe.slice(0, gtIndex)).trim();
  return projectSegment || null;
}

function resolveProjectSlug(): string {
  if (typeof window === "undefined") {
    return PROJECT_FALLBACK_SLUG;
  }
  const leashWindow = window as typeof window & { __LEASH_TITLE_TEXT?: string | null };
  const rawTitle = String(leashWindow.__LEASH_TITLE_TEXT ?? document?.title ?? "").trim();
  const project = extractProjectFromTitle(rawTitle);
  if (project) {
    return slugifyForFilename(project);
  }
  return PROJECT_FALLBACK_SLUG;
}

// Render action details with type-specific formatting
const renderDetail = (a: Action) => {
  const mono = "font-mono text-xs";
  const faint = "text-cyan-400/60";
  const chip = (text: string, tone: "good" | "bad" | "muted" = "muted") => (
    <span className={
      `inline-flex items-center rounded px-2 py-0.5 text-[10px] border ${
        tone === "good" ? "bg-green-500/15 text-green-200 border-green-500/30" :
        tone === "bad" ? "bg-red-500/15 text-red-200 border-red-500/30" :
        "bg-cyan-500/10 text-cyan-200 border-cyan-500/30"
      }`
    }>{text}</span>
  );

  // MCP-centric formatting
  if (a.type.startsWith("mcp/")) {
    return (
      <div className="flex flex-wrap items-center gap-1.5 min-w-0">
        {a.method && <span className={`${mono}`}>{a.method}</span>}
        {a.tool && chip(`tool=${a.tool}`)}
        {a.server && <span className={`${mono} ${faint}`}>server={a.server}</span>}
        {typeof a.status === "number" && chip(String(a.status), a.status >= 400 ? "bad" : "good")}
        {a.transport && <span className={`${mono} ${faint}`}>via {String(a.transport).toUpperCase()}</span>}
        {a.session && <span className={`${mono} ${faint}`}>session={a.session}</span>}
        {typeof a.durationMs === "number" && <span className={`${mono} ${faint}`}>{a.durationMs} ms</span>}
        {a.outcome && a.outcome !== "success" && chip(`!${a.outcome}`, "bad")}
        {a.requestId && <span className={`${mono} ${faint}`}>id={a.requestId}</span>}
      </div>
    );
  }

  // Network/connect formatting
  if (a.type === "net/connect") {
    return (
      <div className="flex flex-wrap items-center gap-1.5 min-w-0">
        <span className={`${mono}`}>{a.name}</span>
        {typeof a.status === "number" && chip(String(a.status), a.status >= 400 ? "bad" : "good")}
        {a.transport && <span className={`${mono} ${faint}`}>via {String(a.transport).toUpperCase()}</span>}
        {a.proto && <span className={`${mono} ${faint}`}>proto {a.proto}</span>}
        {typeof a.durationMs === "number" && <span className={`${mono} ${faint}`}>{a.durationMs} ms</span>}
      </div>
    );
  }

  // Exec formatting
  if (a.type === "proc/exec") {
    return (
      <div className="flex flex-wrap items-center gap-1.5 min-w-0">
        <span className={`${mono}`}>{a.name}</span>
        {typeof a.status === "number" && chip(String(a.status), a.status === 0 ? "good" : "bad")}
        {typeof a.durationMs === "number" && <span className={`${mono} ${faint}`}>{a.durationMs} ms</span>}
      </div>
    );
  }

  // Filesystem and DNS and other misc
  return (
    <div className="flex flex-wrap items-center gap-1.5 min-w-0">
      <span className={`${mono}`}>{a.method ?? a.name}</span>
      {a.tool && chip(`tool=${a.tool}`)}
      {a.server && <span className={`${mono} ${faint}`}>server={a.server}</span>}
      {typeof a.status === "number" && chip(String(a.status), a.status >= 400 ? "bad" : "good")}
      {a.transport && <span className={`${mono} ${faint}`}>via {String(a.transport).toUpperCase()}</span>}
      {a.proto && <span className={`${mono} ${faint}`}>proto {a.proto}</span>}
      {typeof a.durationMs === "number" && <span className={`${mono} ${faint}`}>{a.durationMs} ms</span>}
      {a.requestId && <span className={`${mono} ${faint}`}>id={a.requestId}</span>}
    </div>
  );
};

// Memoized row component to prevent unnecessary re-renders
const ActionRow = memo(({
  action,
  isPending,
  isAdded,
  onAddPolicy
}: {
  action: Action;
  isPending: boolean;
  isAdded: boolean;
  onAddPolicy: (action: { id: string; type: ActionType; name: string }, effect: "permit" | "forbid") => void;
}) => {
  const repeats = action.repeatCount ?? 1;

  return (
    <tr className="border-b border-cyan-500/10 transition-all duration-500 hover:bg-cyan-500/5">
      <td className="p-3 align-middle text-cyan-300/60 text-xs">{timeAgo(action.ts)}</td>
      <td className="p-2.5 align-middle whitespace-nowrap">
        <span className="inline-flex items-center gap-1 text-slate-300">
          {typeIconFor(action.type)}
          <span className="text-xs whitespace-nowrap">{action.type}</span>
          {action.notification && (
            <Badge className="bg-amber-500/20 text-amber-200 border-amber-500/40 px-1 text-[10px]">
              notify
            </Badge>
          )}
        </span>
      </td>
      <td className="p-2.5 align-middle text-xs min-w-0">
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="truncate cursor-default">{renderDetail(action)}</div>
          </TooltipTrigger>
          <TooltipContent className="max-w-2xl">
            {renderDetail(action)}
          </TooltipContent>
        </Tooltip>
      </td>
      <td className="p-2.5 whitespace-nowrap align-middle">
        {action.allowed ? (
          <div className="flex items-center gap-2">
            <span className="relative inline-flex h-2 w-2 rounded-full bg-green-400">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
            </span>
            <span className="text-xs uppercase tracking-wide font-medium text-green-400">
              Allowed
            </span>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <span className="relative inline-flex h-2 w-2 rounded-full bg-red-400">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
            </span>
            <span className="text-xs uppercase tracking-wide font-medium text-red-400">
              Denied
            </span>
          </div>
        )}
      </td>
      <td className="p-2.5 align-middle text-center">
        <span
          data-testid="repeat-count"
          className="inline-flex min-w-[28px] items-center justify-center rounded-full border border-cyan-500/20 bg-slate-900/60 px-2 py-0.5 text-[10px] font-semibold"
          style={{ color: "color-mix(in oklab, var(--color-cyan-400) 70%, transparent)" }}
        >
          {repeats}
        </span>
      </td>
      <td className="p-2.5 whitespace-nowrap align-middle">
        <div className="flex items-center gap-1">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="icon"
                variant="ghost"
                className="text-green-400 hover:text-green-300 hover:bg-green-500/10 h-7 w-7"
                aria-label="Add Allow"
                onClick={() => onAddPolicy(action, "permit")}
                disabled={isPending}
              >
                {isAdded ? <Check className="size-4" /> : <Check className="size-4" />}
              </Button>
            </TooltipTrigger>
            <TooltipContent>Add Allow</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="icon"
                variant="ghost"
                className="text-red-400 hover:text-red-300 hover:bg-red-500/10 h-7 w-7"
                aria-label="Add Deny"
                onClick={() => onAddPolicy(action, "forbid")}
                disabled={isPending}
              >
                <X className="size-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Add Deny</TooltipContent>
          </Tooltip>
        </div>
      </td>
    </tr>
  );
});

ActionRow.displayName = "ActionRow";

const formatDetailForExport = (action: Action): string => {
  const parts: string[] = [];
  const push = (value: string | number | undefined | null) => {
    if (value === undefined || value === null) return;
    const str = String(value);
    if (str.length === 0) return;
    parts.push(str);
  };
  const pushKey = (key: string, value: string | number | undefined | null) => {
    if (value === undefined || value === null) return;
    const str = String(value);
    if (str.length === 0) return;
    parts.push(`${key}=${str}`);
  };

  if (action.type.startsWith("mcp/")) {
    push(action.method);
    pushKey("tool", action.tool);
    pushKey("server", action.server);
    if (typeof action.status === "number") {
      pushKey("status", action.status);
    }
    if (action.transport) {
      pushKey("via", action.transport.toUpperCase());
    }
    pushKey("session", action.session);
    if (typeof action.durationMs === "number") {
      pushKey("durationMs", action.durationMs);
    }
    if (action.outcome && action.outcome !== "success") {
      pushKey("outcome", action.outcome);
    }
    pushKey("id", action.requestId);
    return parts.join(" ");
  }

  if (action.type === "net/connect") {
    push(action.name);
    if (typeof action.status === "number") {
      pushKey("status", action.status);
    }
    if (action.transport) {
      pushKey("via", action.transport.toUpperCase());
    }
    pushKey("proto", action.proto);
    if (typeof action.durationMs === "number") {
      pushKey("durationMs", action.durationMs);
    }
    return parts.join(" ");
  }

  if (action.type === "proc/exec") {
    push(action.name);
    if (typeof action.status === "number") {
      pushKey("status", action.status);
    }
    if (typeof action.durationMs === "number") {
      pushKey("durationMs", action.durationMs);
    }
    return parts.join(" ");
  }

  push(action.method ?? action.name);
  pushKey("tool", action.tool);
  pushKey("server", action.server);
  if (typeof action.status === "number") {
    pushKey("status", action.status);
  }
  if (action.transport) {
    pushKey("via", action.transport.toUpperCase());
  }
  pushKey("proto", action.proto);
  if (typeof action.durationMs === "number") {
    pushKey("durationMs", action.durationMs);
  }
  pushKey("id", action.requestId);

  return parts.join(" ");
};

export function ActionsStream({ instanceId, onPolicyMutated }: { instanceId?: string; onPolicyMutated?: () => void }) {
  const state = useSimulation();
  const [text, setText] = useState("");
  const [debouncedText, setDebouncedText] = useState("");
  const [allowed, setAllowed] = useState<"all" | "allowed" | "denied">("all");
  const [type, setType] = useState<"all" | "mcp" | ActionType>("all");
  const { refresh, patchPolicies, showNotice } = usePolicyBlocksContext();
  const paneRef = useRef<HTMLDivElement | null>(null);
  const [paneHeight, setPaneHeight] = useState<number | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const hoverActiveRef = useRef(false);

  // Enable space/shift+space scrolling when the table is hovered.
  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const handleSpaceScroll = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }
      if (!hoverActiveRef.current) {
        return;
      }

      const key = event.key;
      if (key !== " " && key !== "Spacebar" && key !== "Space") {
        return;
      }

      const container = scrollContainerRef.current;
      if (!container) {
        return;
      }

      event.preventDefault();
      const direction = event.shiftKey ? -1 : 1;
      const pageSize = container.clientHeight > 0 ? container.clientHeight : 240;

      if (typeof container.scrollBy === "function") {
        container.scrollBy({ top: direction * pageSize, behavior: "smooth" });
      } else {
        container.scrollTop += direction * pageSize;
      }
    };

    window.addEventListener("keydown", handleSpaceScroll);
    return () => window.removeEventListener("keydown", handleSpaceScroll);
  }, []);

  // Ensure the events pane fills the viewport while respecting a minimum height.
  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const updatePaneHeight = () => {
      const pane = paneRef.current;
      if (!pane) return;
      const rect = pane.getBoundingClientRect();
      const viewportHeight = window.innerHeight;
      const availableHeight = viewportHeight - rect.top - VIEWPORT_GUTTER_PX;
      if (!Number.isFinite(availableHeight)) {
        return;
      }
      const nextHeight = Math.max(MIN_EVENTS_PANE_HEIGHT, Math.round(availableHeight));
      setPaneHeight((current) => (current === nextHeight ? current : nextHeight));
    };

    let frame = 0;
    const scheduleUpdate = () => {
      cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(updatePaneHeight);
    };

    scheduleUpdate();
    window.addEventListener("resize", scheduleUpdate);

    let observer: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      observer = new ResizeObserver(scheduleUpdate);
      const pane = paneRef.current;
      if (pane) {
        observer.observe(pane);
      }
      if (pane?.parentElement) {
        observer.observe(pane.parentElement);
      }
      const body = document.body;
      if (body) {
        observer.observe(body);
      }
    }

    return () => {
      window.removeEventListener("resize", scheduleUpdate);
      cancelAnimationFrame(frame);
      observer?.disconnect();
    };
  }, []);

  // Debounce text input to reduce re-filtering
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedText(text);
    }, 300);
    return () => clearTimeout(timer);
  }, [text]);

  // Narrower type guard for tab value changes
  const isFilterType = (v: string): v is "all" | "mcp" | ActionType =>
    v === "all" ||
    v === "mcp" ||
    v === "file/open" ||
    v === "file/write" ||
    v === "proc/exec" ||
    v === "net/connect" ||
    v === "mcp/deny" ||
    v === "mcp/allow" ||
    v === "mcp/list" ||
    v === "mcp/call" ||
    v === "mcp/resources" ||
    v === "mcp/prompts" ||
    v === "mcp/init" ||
    v === "mcp/notify";

  const { actions, filteredTotal } = useMemo(() => {
    const filtered = state.recentActions.filter((action) => {
      if (instanceId && action.instanceId !== instanceId) {
        return false;
      }
      if (allowed === "allowed" && !action.allowed) {
        return false;
      }
      if (allowed === "denied" && action.allowed) {
        return false;
      }
      if (type === "mcp") {
        if (!action.type.startsWith("mcp/")) {
          return false;
        }
      } else if (type !== "all" && action.type !== type) {
        return false;
      }
      if (debouncedText) {
        const q = debouncedText.toLowerCase();
        if (!action.name.toLowerCase().includes(q) && !action.id.includes(q)) {
          return false;
        }
      }
      return true;
    });
    const sorted = filtered.slice().reverse();
    const limited = sorted.slice(0, 50);
    return { actions: limited, filteredTotal: sorted.length };
  }, [state.recentActions, instanceId, allowed, type, debouncedText]);

  const actionSummary = useMemo(() => {
    let total = 0;
    let allowedCount = 0;
    let deniedCount = 0;
    for (const action of actions) {
      const repeats = action.repeatCount ?? 1;
      total += repeats;
      if (action.allowed) {
        allowedCount += repeats;
      } else {
        deniedCount += repeats;
      }
    }
    return { total, allowed: allowedCount, denied: deniedCount };
  }, [actions]);

  const summaryLabel = filteredTotal <= actions.length
    ? `${actions.length} shown`
    : `${actions.length} of ${filteredTotal} shown`;

  const [addedId, setAddedId] = useState<string | null>(null);
  const [pendingId, setPendingId] = useState<string | null>(null);
  const hasActions = state.recentActions.length > 0;

  // Memoized callback to prevent row re-renders
  const onAddPolicy = useCallback(async (action: { id: string; type: ActionType; name: string }, effect: "permit" | "forbid") => {
    setPendingId(action.id);
    try {
      const ok = await patchPolicies({
        add: [{
          effect,
          action: { type: action.type, name: action.name },
        }],
      });
      if (!ok) {
        setPendingId(null);
        return;
      }
    } catch (err) {
      console.error("Failed to add policy:", err);
      const msg = err instanceof Error ? err.message : "Policy change failed";
      try { showNotice?.(msg); } catch {}
      setPendingId(null);
      return;
    }

    try {
      await refresh();
    } catch (refreshErr) {
      console.error("Failed to refresh policies:", refreshErr);
    }
    try {
      await Promise.resolve(onPolicyMutated?.());
    } catch (callbackErr) {
      console.error("Policy update callback failed:", callbackErr);
    }
    setAddedId(action.id);
    window.setTimeout(() => setAddedId(null), 1200);
    setPendingId(null);
  }, [patchPolicies, refresh, onPolicyMutated, showNotice]);

  const handleDownload = useCallback(() => {
    if (typeof window === "undefined") return;
    if (state.recentActions.length === 0) return;

    const records = state.recentActions.map((action) => ({
      id: action.id,
      instanceId: action.instanceId,
      name: action.name,
      repeatCount: action.repeatCount ?? 1,
      time: new Date(action.ts).toISOString(),
      event: action.type,
      detail: formatDetailForExport(action),
      decision: action.allowed ? "allowed" : "denied",
    }));

    const eventCount = records.reduce((sum, record) => sum + (record.repeatCount ?? 1), 0);
    const projectSlug = resolveProjectSlug();
    const jsonl = records.map((record) => JSON.stringify(record)).join("\n");
    const blob = new Blob([jsonl || ""], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `leash-${projectSlug}-${eventCount}-events-${stamp}.jsonl`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    window.setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 0);
  }, [state.recentActions]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const handleShortcut = (event: KeyboardEvent) => {
      const key = typeof event.key === "string" ? event.key.toLowerCase() : "";
      if (key !== "d") {
        return;
      }
      const isMacShortcut = event.metaKey && event.ctrlKey;
      const isAltShortcut = event.ctrlKey && event.altKey;
      if (!isMacShortcut && !isAltShortcut) {
        return;
      }
      event.preventDefault();
      handleDownload();
    };

    window.addEventListener("keydown", handleShortcut);
    return () => window.removeEventListener("keydown", handleShortcut);
  }, [handleDownload]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Input
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Filter by name/id..."
          className="max-w-sm bg-slate-900/50 border-cyan-500/30 text-cyan-300 placeholder:text-cyan-400/50"
        />
        <Tabs value={allowed} onValueChange={(v: string) => setAllowed(v as "all" | "allowed" | "denied")}>
          <TabsList className="bg-slate-900/50 border-cyan-500/30">
            <TabsTrigger value="all">All</TabsTrigger>
            <TabsTrigger value="allowed">Allowed</TabsTrigger>
            <TabsTrigger value="denied">Denied</TabsTrigger>
          </TabsList>
        </Tabs>
        <Tabs value={type} onValueChange={(v: string) => setType(isFilterType(v) ? v : "all") }>
            <TabsList className="overflow-x-auto bg-slate-900/50 border-cyan-500/30">
              <TabsTrigger value="all">Any</TabsTrigger>
              <TabsTrigger value="file/open">file/open</TabsTrigger>
              <TabsTrigger value="file/write">file/write</TabsTrigger>
              <TabsTrigger value="proc/exec">proc/exec</TabsTrigger>
              <TabsTrigger value="net/connect">net/connect</TabsTrigger>
              <TabsTrigger value="mcp">mcp</TabsTrigger>
            </TabsList>
          </Tabs>
        <Badge variant="secondary" className="bg-cyan-500/20 text-cyan-300 border-cyan-500/30">
          {summaryLabel}
        </Badge>
        {/* Empty-state guidance */}
        {actions.length === 0 && (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="inline-flex h-6 items-center justify-center rounded-md border border-cyan-500/40 bg-slate-950/80 px-2 text-xs font-semibold text-cyan-200">
                  ?
                </span>
              </TooltipTrigger>
              <TooltipContent hideArrow className="max-w-xs space-y-1 border border-cyan-500/40 bg-slate-950/90 text-cyan-100 shadow-[0_0_12px_rgba(6,182,212,0.25)]">
                <p>No actions yet. If you expect live data:</p>
                <ul className="list-disc space-y-1 pl-4 text-cyan-100/80">
                  <li>Use the Data Source toggle above and switch to Live.</li>
                  <li>Confirm the WebSocket URL shows ws(s)://host:18080/api.</li>
                  <li>Generate activity (open a file, run a command, or make an HTTP request).</li>
                </ul>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
      </div>

      <TooltipProvider>
        <div
          ref={paneRef}
          className="relative flex flex-col overflow-hidden rounded-lg border border-cyan-500/30 bg-slate-900/50 backdrop-blur"
          style={{ minHeight: MIN_EVENTS_PANE_HEIGHT, height: paneHeight ?? undefined }}
        >
          {/* Header glow effect */}
          <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-50" />

          <div
            ref={scrollContainerRef}
            data-testid="actions-scroll-area"
            className="flex-1 overflow-y-auto pr-2 min-h-0"
            style={{ scrollbarGutter: "stable" }}
            onMouseEnter={() => {
              hoverActiveRef.current = true;
            }}
            onMouseLeave={() => {
              hoverActiveRef.current = false;
            }}
          >
            <table className="w-full text-sm table-fixed">
              <colgroup>
                <col className="w-[110px]" />
                <col className="w-[130px]" />
                <col className="min-w-0" />
                <col className="w-[120px]" />
                <col className="w-[48px]" />
                <col className="w-[120px]" />
              </colgroup>
              <thead className="border-b border-cyan-500/20 bg-slate-900/80 sticky top-0 z-10">
                <tr>
                  <th className="text-left p-3 text-cyan-400/70 font-medium uppercase text-xs tracking-wider">
                    <div className="flex items-center gap-2">
                      <Clock className="w-3 h-3" />
                      Time
                    </div>
                  </th>
                  <th className="text-left p-3 text-cyan-400/70 font-medium uppercase text-xs tracking-wider">
                    Event
                  </th>
                  <th className="text-left p-3 text-cyan-400/70 font-medium uppercase text-xs tracking-wider">
                    Detail
                  </th>
                  <th className="text-left p-3 text-cyan-400/70 font-medium uppercase text-xs tracking-wider whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <Shield className="w-3 h-3" />
                      Decision
                    </div>
                  </th>
                  <th aria-hidden="true" className="p-3" />
                  <th className="text-left p-3 text-cyan-400/70 font-medium uppercase text-xs tracking-wider whitespace-nowrap">Policy</th>
                </tr>
              </thead>
              <tbody>
                {actions.map((action) => (
                  <ActionRow
                    key={action.id}
                    action={action}
                    isPending={pendingId === action.id}
                    isAdded={addedId === action.id}
                    onAddPolicy={onAddPolicy}
                  />
                ))}
              </tbody>
            </table>
          </div>

          {/* Bottom status bar */}
          <div className="flex-none px-3 py-2 bg-slate-900/80 border-t border-cyan-500/20 flex items-center justify-between">
            <div className="flex items-center gap-4 text-[10px] text-cyan-400/50 font-mono uppercase">
              <span>Total: {actionSummary.total}</span>
              <span className="text-green-400">
                Allowed: {actionSummary.allowed}
              </span>
              <span className="text-red-400">
                Denied: {actionSummary.denied}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    size="icon"
                    variant="ghost"
                    aria-label="Download events"
                    className="h-8 w-8 text-cyan-400/70 hover:text-cyan-200 hover:bg-cyan-500/10 disabled:text-cyan-500/30"
                    onClick={handleDownload}
                    disabled={!hasActions}
                  >
                    <Download className="size-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Download events</TooltipContent>
              </Tooltip>
              <div className="flex gap-1">
                {Array.from({ length: 8 }).map((_, i) => (
                  <div
                    key={i}
                    className="w-1 h-3 rounded-sm bg-cyan-400/30 animate-pulse"
                    style={{ animationDelay: `${i * 150}ms` }}
                  />
                ))}
              </div>
            </div>
          </div>
        </div>
      </TooltipProvider>
    </div>
  );
}
