"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import DataSourceControls from "@/components/nav/data-source-controls";
import SingleHeader from "@/components/single/header";
import PromptBanner from "@/components/single/prompt-banner";
import CedarEditorCollapsible from "@/components/policy/cedar-editor-collapsible";
import { SecretsPane } from "@/components/secrets/secrets-pane";
import { ActionsStream } from "@/components/actions/stream";
import PolicyBlockCard from "@/components/policy/policy-block-card";
import { fetchPolicyLines, type PolicyLine } from "@/lib/policy/api";
import { SingleProvider } from "@/lib/single/store";
import { useLatestPolicySnapshot, SimulationProvider } from "@/lib/mock/sim";
import { PolicyQueryProvider } from "@/lib/policy/query-provider";
import { PolicyBlocksProvider } from "@/lib/policy/policy-blocks-context";

function ConsoleContent() {
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
    void loadLines();
  }, [loadLines]);

  return (
    <SingleProvider>
      <section className="space-y-4">
        <CedarEditorCollapsible defaultOpen={false} />
        <SecretsPane />
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="order-2 lg:order-1 lg:col-span-2">
            <ActionsStream onPolicyMutated={loadLines} />
          </div>
          <div className="order-1 space-y-3 lg:order-2">
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
  return (
    <SimulationProvider initialMode="live" persist={false}>
      <PolicyQueryProvider>
        <PolicyBlocksProvider>
          <main className="space-y-4 p-6">
            <DataSourceControls />
            <ConsoleContent />
          </main>
        </PolicyBlocksProvider>
      </PolicyQueryProvider>
    </SimulationProvider>
  );
}
