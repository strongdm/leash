"use client";

import { useMemo } from "react";
import { useDataSource } from "@/lib/mock/sim";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function DataSourceControls() {
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
    <div className="mb-6 flex flex-wrap items-center justify-between gap-4 rounded-lg border border-cyan-500/30 bg-slate-900/40 px-4 py-3 backdrop-blur">
      <div className="flex items-center gap-4">
        <div className="relative">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="/logo.svg"
            alt="Leash Logo"
            className="size-16 opacity-90"
            style={{ filter: 'brightness(0) invert(1) sepia(1) saturate(5) hue-rotate(175deg)' }}
          />
          <div className="absolute inset-0 size-16 bg-cyan-400 blur-xl opacity-50 animate-pulse" />
        </div>
        <div>
          <h1
            className="text-6xl font-bold text-transparent bg-clip-text"
            style={{
              backgroundImage: "linear-gradient(90deg, #845EEE 0%, #A04CF0 50%, #C951E7 100%)",
            }}
          >
            leash{" "}
            <span className="text-xl">
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
          <div className="text-xs text-cyan-400/90 tracking-[0.2em] uppercase font-medium">AI Agent Visibility and Control</div>
        </div>
        <div className="ml-6 border-l border-cyan-500/30 pl-6">
          <div className="text-xs uppercase tracking-wide text-cyan-400/70">Data Source</div>
          <div className="mt-1 flex items-center gap-2">
            <span className="text-sm font-semibold text-cyan-200">
              {mode === "sim" ? "Simulated" : "Live"}
            </span>
          </div>
          {mode === "live" && wsUrl && (
            <div className="mt-1 text-xs font-mono text-cyan-400/60 break-all">{wsUrl}</div>
          )}
          {mode === "live" && error && (
            <div className="mt-1 text-xs text-red-400">{error}</div>
          )}
        </div>
      </div>
      <div className="flex items-center gap-3">
        <Badge variant="secondary" className={`border ${statusBadge.tone}`}>
          {statusBadge.label}
        </Badge>
        <Tabs value={mode} onValueChange={(value) => setMode(value as "sim" | "live")}>
          <TabsList className="bg-slate-900/50 border border-cyan-500/30">
            <TabsTrigger value="sim">Simulated</TabsTrigger>
            <TabsTrigger value="live">Live</TabsTrigger>
          </TabsList>
        </Tabs>
      </div>
    </div>
  );
}
