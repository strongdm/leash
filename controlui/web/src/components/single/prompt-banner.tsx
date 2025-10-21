"use client";

import { useSingle } from "@/lib/single/store";
import { Button } from "@/components/ui/button";

export default function PromptBanner() {
  const { prompt, setPrompt } = useSingle();
  if (!prompt) return null;
  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 w-[min(720px,90vw)] border rounded-lg border-amber-500/40 bg-slate-900/90 backdrop-blur shadow-2xl">
      <div className="p-3 text-sm text-amber-200">
        <div className="font-semibold mb-1">Would Deny (simulated)</div>
        <div className="opacity-90">{prompt.action} → {prompt.resource} by {prompt.process}</div>
        <div className="mt-2 flex gap-2">
          <Button size="sm" variant="outline" onClick={() => setPrompt(null)}>Allow once</Button>
          <Button size="sm" variant="outline" onClick={() => setPrompt(null)}>Allow 5m</Button>
          <Button size="sm" variant="outline" onClick={() => setPrompt(null)}>Always allow (exception)</Button>
          <Button size="sm" variant="destructive" onClick={() => setPrompt(null)}>Dismiss</Button>
        </div>
      </div>
    </div>
  );
}

