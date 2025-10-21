"use client";

import { useMemo, useState, useCallback, useRef, useEffect } from "react";
import ReactFlow, { 
  Background, 
  Controls, 
  MiniMap, 
  Node, 
  Edge,
  ReactFlowProvider,
  ConnectionMode,
  MarkerType
} from "reactflow";
import "reactflow/dist/style.css";
import { useSimulation } from "@/lib/mock/sim";
import { motion, AnimatePresence } from "framer-motion";
import {
  Cpu,
  SquareTerminal,
  Bot,
  Boxes,
  Network,
  FileText,
  Terminal,
  List,
  Globe,
  Activity,
  Shield,
  Database,
  MessageSquare,
  Bell,
  Power,
} from "lucide-react";
import { timeAgo } from "@/lib/time";
import type { ActionType } from "@/lib/mock/types";

type Agent = "Claude Code" | "Codex" | "Cursor" | "Other";

const icons: Record<Agent, React.ComponentType<{ className?: string }>> = {
  "Claude Code": Bot,
  Codex: SquareTerminal,
  Cursor: Cpu,
  Other: Boxes,
};

const agentColors: Record<Agent, { gradient: string; glow: string }> = {
  "Claude Code": { 
    gradient: "from-cyan-400 via-blue-500 to-purple-500",
    glow: "cyan"
  },
  Codex: { 
    gradient: "from-green-400 via-emerald-500 to-teal-500",
    glow: "green"
  },
  Cursor: { 
    gradient: "from-purple-400 via-pink-500 to-rose-500",
    glow: "purple"
  },
  Other: { 
    gradient: "from-amber-400 via-orange-500 to-red-500",
    glow: "amber"
  },
};

function mapAgentCategory(agent: string | undefined): Agent {
  if (agent === "Claude Code" || agent === "Codex" || agent === "Cursor") return agent;
  return "Other";
}

function CyberpunkNode({ data }: { data: { agent: Agent; title: string; subtitle: string; footnote?: string; status: string; instanceId: string } }) {
  const Icon = icons[data.agent] ?? Boxes;
  const online = data.status === "online";
  const colors = agentColors[data.agent] ?? agentColors.Other;

  return (
    <div className="relative group cursor-pointer">
      {/* Main node container */}
      <div 
        className={`
          relative w-24 h-24 rounded-xl
          transition-all duration-300 group-hover:scale-110
        `}
      >
        {/* Icon container */}
        <div className="relative h-full flex flex-col items-center justify-center">
          <div className={`relative p-3.5 rounded-xl bg-gradient-to-br ${colors.gradient} shadow-lg`}>
            <Icon className="w-10 h-10 text-white drop-shadow-md" />
          </div>
          
          {/* Platform label */}
          <div className="mt-3 px-2 text-center">
            <div className="text-xs font-bold text-cyan-300 uppercase tracking-wide truncate max-w-[84px]">
              {data.title}
            </div>
            <div className="text-[10px] text-cyan-200/80 font-mono truncate max-w-[80px]">
              {data.subtitle}
            </div>
            {data.footnote && (
              <div className="text-[10px] text-slate-400/80 truncate max-w-[80px]">
                {data.footnote}
              </div>
            )}
          </div>
        </div>

        {/* Status indicator */}
        {online && (
          <div className="absolute -top-1 -right-1">
            <div className="relative">
              <span className="absolute inline-flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const nodeTypes = { cyberpunkNode: CyberpunkNode };

// Custom minimap node colors
const nodeColor = (node: Node) => {
  const agent = node.data?.agent as Agent;
  const online = node.data?.status === 'online';
  if (!online) return '#4b5563';
  
  switch(agent) {
    case 'Claude Code': return '#22d3ee';
    case 'Codex': return '#10b981';
    case 'Cursor': return '#a855f7';
    default: return '#f59e0b';
  }
};

export default function InstancesFlow() {
  const state = useSimulation();
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoverId, setHoverId] = useState<string | null>(null);
  const [dataStreams, setDataStreams] = useState<Array<{id: string, from: string, to: string}>>([]);

  // Generate animated data streams between nodes
  useEffect(() => {
    const interval = setInterval(() => {
      const instances = [...state.instances.values()].filter(i => i.status === 'online');
      if (instances.length > 1) {
        const from = instances[Math.floor(Math.random() * instances.length)];
        const to = instances[Math.floor(Math.random() * instances.length)];
        if (from.id !== to.id) {
          const streamId = `stream-${Date.now()}`;
          setDataStreams(prev => [...prev, { id: streamId, from: from.id, to: to.id }]);
          setTimeout(() => {
            setDataStreams(prev => prev.filter(s => s.id !== streamId));
          }, 2000);
        }
      }
    }, 800);
    return () => clearInterval(interval);
  }, [state.instances]);

  const { nodes, edges } = useMemo(() => {
    // Grid layout with dynamic spacing
    const columns = 4;
    const spacing = 200;
    const startX = 100;
    const startY = 100;
    
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const instances = [...state.instances.values()];
    
    instances.forEach((inst, index) => {
      const col = index % columns;
      const row = Math.floor(index / columns);
      
      nodes.push({
        id: inst.id,
        type: "cyberpunkNode",
        position: { 
          x: startX + col * spacing + (row % 2) * 50, // Offset odd rows
          y: startY + row * spacing 
        },
        data: {
          agent: mapAgentCategory(inst.agent) as Agent,
          title: (inst.displayName ?? inst.agent ?? "unknown").slice(0, 24),
          subtitle: inst.id.toUpperCase(),
          footnote: inst.lastCommand?.slice(0, 28),
          status: inst.status,
          instanceId: inst.id,
        },
      });
    });

    // Create dynamic edges for data streams
    dataStreams.forEach(stream => {
      edges.push({
        id: stream.id,
        source: stream.from,
        target: stream.to,
        type: 'smoothstep',
        animated: true,
        style: {
          stroke: '#22d3ee',
          strokeWidth: 2,
          opacity: 0.6,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#22d3ee',
        },
      });
    });

    return { nodes, edges };
  }, [state.instances, dataStreams]);

  const onNodeClick = useCallback(() => {
    // Navigation to instance detail disabled; page routes removed.
  }, []);

  const [hoverPos, setHoverPos] = useState<{ x: number; y: number } | null>(null);
  const hoverTickRef = useRef<number | null>(null);

  const updateHoverPos = useCallback((id: string) => {
    if (!containerRef.current) return;
    const containerRect = containerRef.current.getBoundingClientRect();
    const el = containerRef.current.querySelector(`.react-flow__node[data-id="${CSS.escape(id)}"]`) as HTMLElement | null;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const x = r.right - containerRect.left + 10;
    const y = r.top - containerRect.top + r.height / 2;
    setHoverPos({ x, y });
  }, []);

  const onNodeMouseEnter = useCallback((event: React.MouseEvent, n: Node) => {
    setHoverId(n.id);
    updateHoverPos(n.id);
  }, [updateHoverPos]);

  const onNodeMouseMove = useCallback((event: React.MouseEvent, n: Node) => {
    updateHoverPos(n.id);
  }, [updateHoverPos]);

  const onNodeMouseLeave = useCallback(() => {
    setHoverId(null);
    setHoverPos(null);
  }, []);

  // Keep tooltip adjacent while hovering, even during zoom/pan/layout churn.
  useEffect(() => {
    if (!hoverId) {
      if (hoverTickRef.current) {
        cancelAnimationFrame(hoverTickRef.current);
        hoverTickRef.current = null;
      }
      return;
    }
    const tick = () => {
      updateHoverPos(hoverId);
      hoverTickRef.current = requestAnimationFrame(tick);
    };
    hoverTickRef.current = requestAnimationFrame(tick);
    return () => {
      if (hoverTickRef.current) cancelAnimationFrame(hoverTickRef.current);
      hoverTickRef.current = null;
    };
  }, [hoverId, updateHoverPos]);

  return (
    <div ref={containerRef} className="relative w-full h-[600px] bg-slate-950 rounded-lg overflow-hidden">
      {/* Subtle animated background grid */}
      <div className="absolute inset-0 opacity-10">
        <div 
          className="absolute inset-0"
          style={{
            backgroundImage: `
              linear-gradient(rgba(34, 211, 238, 0.3) 1px, transparent 1px),
              linear-gradient(90deg, rgba(34, 211, 238, 0.3) 1px, transparent 1px)
            `,
            backgroundSize: '50px 50px',
            animation: 'grid-move 30s linear infinite',
          }}
        />
      </div>

      <ReactFlowProvider>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          minZoom={0.3}
          maxZoom={2}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          connectionMode={ConnectionMode.Loose}
          proOptions={{ hideAttribution: true }}
          onNodeClick={onNodeClick}
          onNodeMouseEnter={onNodeMouseEnter}
          onNodeMouseMove={onNodeMouseMove}
          onNodeMouseLeave={onNodeMouseLeave}
          className="react-flow-cyberpunk"
        >
          <MiniMap 
            nodeColor={nodeColor}
            nodeStrokeWidth={3}
            pannable 
            zoomable
            className="!bg-slate-900/80 !border-cyan-500/30"
            maskColor="rgb(15, 23, 42, 0.8)"
          />
          <Controls 
            position="bottom-right"
            className="!bg-slate-900/80 !border-cyan-500/30 !shadow-lg"
          />
          <Background 
            gap={50} 
            size={2}
            color="#0891b2"
            className="opacity-10"
          />
        </ReactFlow>
      </ReactFlowProvider>

      {/* Hover tooltip */}
      <AnimatePresence>
        {hoverId && hoverPos && (() => {
          const instance = state.instances.get(hoverId);
          if (!instance) return null;
          
          // Get recent actions for this instance
          const recentActions = state.recentActions
            .filter(a => a.instanceId === hoverId)
            .slice(-10);
          const deniedCount = recentActions.reduce((sum, action) => {
            const repeats = action.repeatCount ?? 1;
            return sum + (action.allowed ? 0 : repeats);
          }, 0);
          const totalCount = recentActions.reduce((sum, action) => sum + (action.repeatCount ?? 1), 0);
          // Count action types for badges
          const typeCounts = new Map<ActionType, number>();
          for (const a of recentActions) {
            const t = a.type as ActionType;
            const repeats = a.repeatCount ?? 1;
            typeCounts.set(t, (typeCounts.get(t) ?? 0) + repeats);
          }
          const topTypes = [...typeCounts.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
          const typeIcon = (t: ActionType) => {
            switch (t) {
              case "file/open":
              case "file/write":
                return <FileText className="w-3 h-3" />;
              case "net/connect":
                return <Network className="w-3 h-3" />;
              case "proc/exec":
                return <Terminal className="w-3 h-3" />;
              case "fs/list":
                return <List className="w-3 h-3" />;
              case "dns/resolve":
                return <Globe className="w-3 h-3" />;
              case "mcp/deny":
              case "mcp/allow":
                return <Shield className="w-3 h-3" />;
              case "mcp/list":
                return <List className="w-3 h-3" />;
              case "mcp/call":
                return <Terminal className="w-3 h-3" />;
              case "mcp/resources":
                return <Database className="w-3 h-3" />;
              case "mcp/prompts":
                return <MessageSquare className="w-3 h-3" />;
              case "mcp/init":
                return <Power className="w-3 h-3" />;
              case "mcp/notify":
                return <Bell className="w-3 h-3" />;
            }
          };
          
          return (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className="absolute z-50 bg-slate-950/95 border border-cyan-500/50 p-3 rounded-lg max-w-xs backdrop-blur-xl shadow-2xl"
              style={{ 
                left: Math.min(hoverPos.x, 800),  // Keep within bounds
                top: Math.max(hoverPos.y, 20)
              }}
            >
              <div className="text-xs space-y-2">
                <div className="flex items-center gap-2">
                  <Activity className="w-3 h-3 text-cyan-400" />
                  <span className="text-cyan-400 font-semibold">{instance.displayName ?? instance.agent}</span>
                </div>
                <div className="text-cyan-300/70 space-y-1">
                  <div>Identifier: {instance.id}</div>
                  <div>Platform: {instance.platform}</div>
                  {instance.lastCommand && <div>Last command: {instance.lastCommand}</div>}
                  <div>Status: <span className={instance.status === 'online' ? 'text-green-400' : 'text-gray-400'}>{instance.status}</span></div>
                  <div>Last seen: {timeAgo(instance.lastSeen)}</div>
                </div>
                <div className="pt-2 border-t border-cyan-500/20">
                  <div className="text-cyan-400/70">Recent activity</div>
                  <div className="flex items-center gap-3 mt-1">
                    <span className="text-cyan-300">{totalCount} actions</span>
                    {deniedCount > 0 && (
                      <span className="text-red-400">{deniedCount} denied</span>
                    )}
                  </div>
                  {topTypes.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {topTypes.map(([t, c]) => (
                        <span key={t} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300">
                          {typeIcon(t)}
                          <span className="uppercase tracking-wide text-[10px] opacity-80">{t.split('/')[1]}</span>
                          <span className="text-[10px] font-mono">{c}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="flex gap-2 mt-2">
                  <span className={`px-2 py-1 rounded text-[10px] ${
                    instance.status === 'online' 
                      ? 'bg-green-500/20 text-green-400' 
                      : 'bg-gray-500/20 text-gray-400'
                  }`}>
                    {instance.status.toUpperCase()}
                  </span>
                  <span className="px-2 py-1 rounded bg-cyan-500/20 text-cyan-400 text-[10px]">
                    ID: {instance.id.slice(0, 8)}
                  </span>
                </div>
              </div>
            </motion.div>
          );
        })()}
      </AnimatePresence>

      {/* Corner indicators */}
      <div className="absolute top-4 left-4 text-xs text-cyan-400/80 font-mono">
        LEASH://NETWORK.GRAPH
      </div>
      <div className="absolute bottom-4 left-4 text-xs text-cyan-400/80 font-mono flex items-center gap-2">
        <span className="inline-block w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
        LIVE
      </div>
    </div>
  );
}
