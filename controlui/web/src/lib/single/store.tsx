"use client";

import React, { createContext, useContext, useState } from "react";

export type SingleMode = "record" | "shadow" | "enforce";

export type SingleState = {
  mode: SingleMode;
  setMode: (m: SingleMode) => void;
  paused: boolean;
  setPaused: (v: boolean) => void;
  profile: string | null;
  setProfile: (p: string | null) => void;
  prompt: null | { action: string; resource: string; process: string };
  setPrompt: (p: SingleState["prompt"]) => void;
};

const Ctx = createContext<SingleState | null>(null);

export function SingleProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<SingleMode>("record");
  const [paused, setPaused] = useState(false);
  const [profile, setProfile] = useState<string | null>("Developer Default");
  const [prompt, setPrompt] = useState<SingleState["prompt"]>(null);
  const value: SingleState = {
    mode,
    setMode,
    paused,
    setPaused,
    profile,
    setProfile,
    prompt,
    setPrompt,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSingle() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useSingle must be used within SingleProvider");
  return ctx;
}

// Optional accessor for components that can operate without a SingleProvider.
// Returns null when not inside the provider rather than throwing.
export function useSingleOptional() {
  return useContext(Ctx);
}
