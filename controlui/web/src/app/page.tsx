"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import DataSourceControls from "@/components/nav/data-source-controls";
import type { PageTab } from "@/components/nav/data-source-controls";
import SingleHeader from "@/components/single/header";
import PromptBanner from "@/components/single/prompt-banner";
import CedarEditor from "@/components/policy/cedar-editor";
import { ActionsStream } from "@/components/actions/stream";
import PolicyBlockCard from "@/components/policy/policy-block-card";
import { fetchPolicyLines, type PolicyLine } from "@/lib/policy/api";
import { SingleProvider } from "@/lib/single/store";
import { useLatestPolicySnapshot, SimulationProvider } from "@/lib/mock/sim";
import { PolicyQueryProvider } from "@/lib/policy/query-provider";
import { PolicyBlocksProvider } from "@/lib/policy/policy-blocks-context";

function ConsoleContent({ activeTab }: { activeTab: PageTab }) {
  const [policyLines, setPolicyLines] = useState<PolicyLine[]>([]);
  const latestRequestId = useRef(0);
  const latestPolicySnapshot = useLatestPolicySnapshot();

  const loadLines = useCallback(async () => {
    try {
      const requestId = ++latestRequestId.current;
      const lines = await fetchPolicyLines();
      if (requestId === latestRequestId.current) {
        setPolicyLines(lines);
      }
    } catch (err) {
      console.error("Failed to load policy lines:", err);
    }
  }, []);

  useEffect(() => {
    void loadLines();
  }, [loadLines]);

  useEffect(() => {
    if (!latestPolicySnapshot) return;
    if (Array.isArray(latestPolicySnapshot.lines)) {
      setPolicyLines(latestPolicySnapshot.lines);
    } else {
      void loadLines();
    }
  }, [latestPolicySnapshot, loadLines]);

  const handlePolicyRemoved = useCallback((id: string) => {
    setPolicyLines((prev) => prev.filter((line) => line.id !== id));
  }, []);

  return (
    <SingleProvider>
      <section className="space-y-4">
        <div className={activeTab !== "events" ? "hidden" : undefined}>
          <ActionsStream onPolicyMutated={loadLines} />
        </div>
        <div className={activeTab !== "policy" ? "hidden" : "grid grid-cols-1 gap-4 lg:grid-cols-3"}>
          <div className="lg:col-span-2">
            <CedarEditor />
          </div>
          <div className="space-y-3">
            <SingleHeader />
            {policyLines.map((line) => (
              <PolicyBlockCard key={line.id} line={line} onRemoved={handlePolicyRemoved} />
            ))}
          </div>
        </div>
        <PromptBanner />
      </section>
    </SingleProvider>
  );
}

export default function SingleConsolePage() {
  const [activeTab, setActiveTab] = useState<PageTab>("events");

  return (
    <SimulationProvider initialMode="live" persist={false}>
      <PolicyQueryProvider>
        <PolicyBlocksProvider>
          <main className="space-y-3 px-4 py-3">
            <DataSourceControls activeTab={activeTab} onTabChange={setActiveTab} />
            <ConsoleContent activeTab={activeTab} />
          </main>
        </PolicyBlocksProvider>
      </PolicyQueryProvider>
    </SimulationProvider>
  );
}
