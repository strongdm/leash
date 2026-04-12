"use client";

import { useMemo } from "react";
import { useDataSource } from "@/lib/mock/sim";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

export type PageTab = "events" | "policy";

type Props = {
  activeTab?: PageTab;
  onTabChange?: (tab: PageTab) => void;
};

export default function DataSourceControls({ activeTab, onTabChange }: Props) {
  const { mode, setMode, status, error, wsUrl } = useDataSource();

  const statusBadge = useMemo(() => {
    if (mode === "sim") {
      return { label: "Simulated", tone: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40" };
    }
    switch (status) {
      case "ready":
        return { label: "Connected", tone: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40" };
      case "connecting":
        return { label: "Connecting", tone: "bg-amber-500/20 text-amber-300 border-amber-500/40" };
      case "error":
        return { label: "Error", tone: "bg-red-500/20 text-red-300 border-red-500/40" };
      default:
        return { label: "Idle", tone: "bg-cyan-500/20 text-cyan-300 border-cyan-500/40" };
    }
  }, [mode, status]);

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-cyan-500/30 bg-slate-900/40 px-4 py-2 backdrop-blur">
      <div className="flex items-center gap-3">
        <div className="relative">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="/logo.svg"
            alt="Leash Logo"
            className="size-9 opacity-90"
            style={{ filter: 'brightness(0) invert(1) sepia(1) saturate(5) hue-rotate(175deg)' }}
          />
          <div className="absolute inset-0 size-9 bg-cyan-400 blur-lg opacity-40" />
        </div>
        <div>
          <h1
            className="text-2xl font-bold text-transparent bg-clip-text leading-tight"
            style={{
              backgroundImage: "linear-gradient(90deg, #845EEE 0%, #A04CF0 50%, #C951E7 100%)",
            }}
          >
            leash{" "}
            <span className="text-xs font-medium">
              by{" "}
              <a
                href="https://www.strongdm.com"
                className="text-inherit no-underline cursor-pointer hover:no-underline focus:no-underline active:no-underline"
                target="_blank"
                rel="noreferrer noopener"
              >
                StrongDM
              </a>
            </span>
          </h1>
          <div className="text-[10px] text-cyan-400/80 tracking-[0.15em] uppercase font-medium">AI Agent Visibility and Control</div>
        </div>
        <div className="ml-3 border-l border-cyan-500/30 pl-3 flex items-center gap-2">
          <Tabs value={mode} onValueChange={(value) => setMode(value as "sim" | "live")}>
            <TabsList className="bg-slate-900/50 border border-cyan-500/30">
              <TabsTrigger value="sim">Simulated</TabsTrigger>
              <TabsTrigger value="live">Live</TabsTrigger>
            </TabsList>
          </Tabs>
          <Badge variant="secondary" className={`h-9 border ${statusBadge.tone}`}>
            {statusBadge.label}
          </Badge>
          {mode === "live" && wsUrl && (
            <span className="text-[10px] font-mono text-cyan-400/50 max-w-[200px] truncate">{wsUrl}</span>
          )}
          {mode === "live" && error && (
            <span className="text-[10px] text-red-400">{error}</span>
          )}
        </div>
      </div>
      <div className="flex items-center gap-3">
        {activeTab && onTabChange && (
          <Tabs value={activeTab} onValueChange={(v) => onTabChange(v as PageTab)}>
            <TabsList className="bg-slate-900/50 border border-cyan-500/30">
              <TabsTrigger value="events">Events</TabsTrigger>
              <TabsTrigger value="policy">Policy</TabsTrigger>
            </TabsList>
          </Tabs>
        )}
      </div>
    </div>
  );
}
