export type SecretRecord = {
  id: string;
  value: string;
  placeholder: string;
  activations: number;
};

export type SecretUpsertPayload = {
  id?: string;
  value: string;
};

type SecretResponse = {
  value?: string;
  placeholder?: string;
  activations?: number;
};

type ErrorPayload = {
  error?: { message?: string } | string;
  message?: string;
};

function resolveApiBase(): string {
  if (typeof window !== "undefined") {
    const fromEnv = process.env.NEXT_PUBLIC_LEASH_API_BASE_URL;
    if (fromEnv) {
      return fromEnv.replace(/\/$/, "");
    }

    const { protocol, hostname, port } = window.location;
    if (port === "3000" || port === "") {
      return `${protocol}//${hostname}:18080`;
    }
    return `${protocol}//${hostname}${port ? `:${port}` : ""}`;
  }
  return (process.env.NEXT_PUBLIC_LEASH_API_BASE_URL || "http://127.0.0.1:18080").replace(/\/$/, "");
}

function toSecretRecord(id: string, payload: SecretResponse | undefined): SecretRecord {
  return {
    id,
    value: payload?.value ?? "",
    placeholder: payload?.placeholder ?? "",
    activations: typeof payload?.activations === "number" ? payload.activations : 0,
  };
}

function extractError(message: string, payload: ErrorPayload | null): Error {
  if (!payload) return new Error(message);
  if (typeof payload === "string") return new Error(payload);

  const fromRoot = typeof payload.message === "string" && payload.message.trim().length > 0
    ? payload.message.trim()
    : undefined;

  if (fromRoot) return new Error(fromRoot);

  const errorField = payload.error;
  if (typeof errorField === "string" && errorField.trim().length > 0) {
    return new Error(errorField.trim());
  }
  if (errorField && typeof errorField === "object" && typeof errorField.message === "string" && errorField.message.trim().length > 0) {
    return new Error(errorField.message.trim());
  }
  return new Error(message);
}

async function handleError(res: Response, fallback: string): Promise<never> {
  let parsed: ErrorPayload | null = null;
  try {
    parsed = (await res.json()) as ErrorPayload;
  } catch {
    // ignore JSON parsing problems
  }
  throw extractError(fallback, parsed);
}

export async function fetchSecrets(): Promise<SecretRecord[]> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/secrets`, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
    cache: "no-store",
  });

  if (!res.ok) {
    await handleError(res, `Secrets API returned ${res.status}`);
  }

  const raw = (await res.json()) as Record<string, SecretResponse> | null;
  if (!raw) {
    return [];
  }

  return Object.entries(raw)
    .map(([id, payload]) => toSecretRecord(id, payload))
    .sort((a, b) => a.id.localeCompare(b.id));
}

export async function upsertSecret(pathId: string, payload: SecretUpsertPayload): Promise<SecretRecord> {
  const base = resolveApiBase();
  const targetId = pathId || payload.id || "";
  const res = await fetch(`${base}/api/secrets/${encodeURIComponent(targetId)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    await handleError(res, `Failed to upsert secret (${res.status})`);
  }

  const body = (await res.json()) as SecretRecord;
  return {
    id: body.id,
    value: body.value,
    placeholder: body.placeholder,
    activations: typeof body.activations === "number" ? body.activations : 0,
  };
}

export async function deleteSecret(id: string): Promise<void> {
  const base = resolveApiBase();
  const res = await fetch(`${base}/api/secrets/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });

  if (!res.ok && res.status !== 204) {
    await handleError(res, `Failed to delete secret (${res.status})`);
  }
}
