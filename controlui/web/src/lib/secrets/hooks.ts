"use client";

import { useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import type { SecretRecord, SecretUpsertPayload } from "./api";
import { deleteSecret, fetchSecrets, upsertSecret } from "./api";
import { useDataSource } from "@/lib/mock/sim";

const secretKeys = {
  list: () => ["secrets", "list"] as const,
};

type UpsertArgs = {
  pathId: string;
  payload: SecretUpsertPayload;
};

type DeleteArgs = {
  id: string;
};

export function useSecretsQuery() {
  return useQuery({
    queryKey: secretKeys.list(),
    queryFn: fetchSecrets,
    staleTime: 5_000,
  });
}

export function useSecretUpsert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ pathId, payload }: UpsertArgs) => upsertSecret(pathId, payload),
    onSuccess: (record, { pathId }) => {
      queryClient.setQueryData<SecretRecord[]>(secretKeys.list(), (current) => {
        const next = Array.isArray(current) ? current.filter((item) => item.id !== pathId && item.id !== record.id) : [];
        next.push(record);
        next.sort((a, b) => a.id.localeCompare(b.id));
        return next;
      });
    },
  });
}

export function useSecretDelete() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id }: DeleteArgs) => deleteSecret(id),
    onSuccess: (_, { id }) => {
      queryClient.setQueryData<SecretRecord[]>(secretKeys.list(), (current) => {
        if (!Array.isArray(current)) return current;
        return current.filter((item) => item.id !== id);
      });
    },
  });
}

type SecretActivationPayload = {
  id: string;
  activations: number;
};

type WebsocketEnvelope = {
  event?: string;
  payload?: unknown;
};

function parseWebsocketBatch(raw: string): WebsocketEnvelope[] {
  if (typeof raw !== "string" || raw.trim().length === 0) {
    return [];
  }
  const lines = raw.includes("\n") ? raw.split(/\r?\n/) : [raw];
  const out: WebsocketEnvelope[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as WebsocketEnvelope);
    } catch (err) {
      console.warn("[Secrets] Failed to parse websocket payload", err);
    }
  }
  return out;
}

function asActivationPayload(value: unknown): SecretActivationPayload | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const id = typeof record.id === "string" ? record.id : undefined;
  const activations = typeof record.activations === "number" ? record.activations : undefined;
  if (!id || typeof activations !== "number") {
    return null;
  }
  return { id, activations };
}

export function useSecretsActivationListener(enabled = true, onActivation?: (secretId?: string) => void) {
  const { wsUrl, connectionVersion, mode } = useDataSource();
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!enabled) return () => undefined;
    if (typeof window === "undefined") return () => undefined;
    if (!wsUrl || wsUrl.trim().length === 0) return () => undefined;
    if (mode !== "live") return () => undefined;

    let cancelled = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let attempts = 0;
    let awaitingInitialReplay = false;

    const cleanupSocket = () => {
      if (socket) {
        try {
          socket.onopen = null;
          socket.onclose = null;
          socket.onerror = null;
          socket.onmessage = null;
          socket.close();
        } catch {
          // ignore
        }
        socket = null;
      }
    };

    const scheduleReconnect = () => {
      if (cancelled) return;
      attempts += 1;
      const delay = Math.min(5_000, attempts * 1_000);
      reconnectTimer = window.setTimeout(connect, delay);
    };

    const handleMessage = (event: MessageEvent) => {
      if (cancelled) return;
      const data = typeof event.data === "string" ? event.data : "";
      console.log("[Secrets WebSocket] Received message:", data);
      const envelopes = parseWebsocketBatch(data);
      const activatedSecretIds = new Set<string>();
      envelopes.forEach((entry) => {
        console.log("[Secrets WebSocket] Processing envelope:", entry);
        if (entry.event !== "secret.activation") return;
        const payload = asActivationPayload(entry.payload);
        if (!payload) return;
        console.log("[Secrets WebSocket] Activation payload:", payload);
        activatedSecretIds.add(payload.id);
        queryClient.setQueryData<SecretRecord[]>(secretKeys.list(), (current) => {
          if (!Array.isArray(current)) return current;
          return current.map((secret) =>
            secret.id === payload.id
              ? { ...secret, activations: payload.activations }
              : secret,
          );
        });
      });
      if (activatedSecretIds.size > 0 && onActivation && !awaitingInitialReplay) {
        activatedSecretIds.forEach((secretId) => {
          console.log("[Secrets WebSocket] Calling onActivation callback with secretId:", secretId);
          onActivation(secretId);
        });
      }
      awaitingInitialReplay = false;
    };

    const connect = () => {
      if (cancelled) return;
      cleanupSocket();
      try {
        socket = new WebSocket(wsUrl);
      } catch (err) {
        console.warn("[Secrets] Failed to open websocket", err);
        scheduleReconnect();
        return;
      }
      attempts = 0;
      if (!socket) return;
      // The hub replays a bulk history payload immediately after each connection.
      // We still update cached activations from that replay, but we suppress the
      // animation callback so rows don't flicker just because the socket bounced.
      awaitingInitialReplay = true;
      socket.onmessage = handleMessage;
      socket.onerror = () => {
        if (cancelled) return;
        scheduleReconnect();
      };
      socket.onclose = () => {
        if (cancelled) return;
        scheduleReconnect();
      };
    };

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer);
      }
      cleanupSocket();
    };
  }, [enabled, wsUrl, connectionVersion, mode, queryClient, onActivation]);
}

export { secretKeys };
