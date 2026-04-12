"use client";

import React, { createContext, useContext, useMemo, useState } from "react";

export type SingleMode = "record" | "enforce";

export type SingleState = {
  mode: SingleMode;
  setMode: (m: SingleMode) => void;
  prompt: null | { action: string; resource: string; process: string };
  setPrompt: (p: SingleState["prompt"]) => void;
};

const Ctx = createContext<SingleState | null>(null);

export function SingleProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<SingleMode>("record");
  const [prompt, setPrompt] = useState<SingleState["prompt"]>(null);
  const value = useMemo<SingleState>(
    () => ({ mode, setMode, prompt, setPrompt }),
    [mode, prompt],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSingle() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useSingle must be used within SingleProvider");
  return ctx;
}
