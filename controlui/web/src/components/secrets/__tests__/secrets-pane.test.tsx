import type { PropsWithChildren } from "react";
import { describe, beforeEach, afterEach, it, expect, vi, beforeAll, afterAll } from "vitest";
import { render, screen, waitFor, act, renderHook, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { SecretRecord } from "@/lib/secrets/api";
import { secretKeys, useSecretsActivationListener } from "@/lib/secrets/hooks";
import { SecretsPane } from "../secrets-pane";

type StoreRecord = SecretRecord;

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";

const store = new Map<string, StoreRecord>();
let placeholderSeed = 0;

function generatePlaceholder(length: number): string {
  if (length <= 0) return "";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += alphabet[(placeholderSeed + i) % alphabet.length];
  }
  placeholderSeed += 1;
  return result;
}

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  public onmessage: ((event: MessageEvent) => void) | null = null;
  public onerror: ((event: Event) => void) | null = null;
  public onclose: ((event: Event) => void) | null = null;

  constructor(public url: string) {
    MockWebSocket.instances.push(this);
  }

  close() {
    this.onclose?.(new Event("close"));
  }
}

function installMockWebSocket(): () => void {
  const originalWebSocket = global.WebSocket;
  vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
  MockWebSocket.instances = [];
  return () => {
    vi.unstubAllGlobals();
    global.WebSocket = originalWebSocket;
  };
}

// Mirror of ACTIVATION_BURST_WINDOW_MS for test timing assertions.
const BURST_WINDOW_MS = 600;

vi.mock("@/lib/secrets/api", () => ({
  fetchSecrets: vi.fn(async () => {
    return Array.from(store.values()).sort((a, b) => a.id.localeCompare(b.id)).map((secret) => ({ ...secret }));
  }),
  upsertSecret: vi.fn(async (pathId: string, payload: { id?: string; value: string }) => {
    const targetId = (payload.id ?? pathId ?? "").trim();
    if (!targetId || !/^[a-zA-Z0-9_]+$/.test(targetId)) {
      throw new Error("invalid id");
    }
    const existing = store.get(pathId);
    if (existing) {
      if (targetId !== pathId && store.has(targetId)) {
        throw new Error("secret already exists");
      }
      const next: StoreRecord = {
        id: targetId,
        value: payload.value,
        placeholder: payload.value !== existing.value ? generatePlaceholder(payload.value.length) : existing.placeholder,
        activations: existing.activations,
      };
      store.delete(pathId);
      store.set(targetId, next);
      return { ...next };
    }
    if (store.has(targetId)) {
      throw new Error("secret already exists");
    }
    const record: StoreRecord = {
      id: targetId,
      value: payload.value,
      placeholder: generatePlaceholder(payload.value.length),
      activations: 0,
    };
    store.set(targetId, record);
    return { ...record };
  }),
  deleteSecret: vi.fn(async (id: string) => {
    if (id === "fail_delete") {
      throw new Error("delete failed");
    }
    if (!store.delete(id)) {
      throw new Error("secret not found");
    }
  }),
}));

const dataSourceState = {
  mode: "sim" as "sim" | "live",
  setMode: vi.fn(),
  status: "ready" as const,
  error: null as string | null,
  wsUrl: "ws://example/api",
  connectionVersion: 0,
};

function updateDataSource(partial: Partial<typeof dataSourceState>) {
  Object.assign(dataSourceState, partial);
}

vi.mock("@/lib/mock/sim", () => ({
  useDataSource: () => dataSourceState,
}));

function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
}

function renderWithClient(ui: React.ReactElement) {
  const queryClient = createQueryClient();
  const result = render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
  return { queryClient, ...result };
}

async function openSecretsPane() {
  const toggle = await screen.findByRole("button", { name: /Secrets/i });
  if (toggle.getAttribute("aria-expanded") !== "true") {
    fireEvent.click(toggle);
  }
}

beforeEach(() => {
  placeholderSeed = 0;
  store.clear();
  store.set("alpha", {
    id: "alpha",
    value: "one",
    placeholder: generatePlaceholder(3),
    activations: 0,
  });
  store.set("beta", {
    id: "beta",
    value: "two",
    placeholder: generatePlaceholder(3),
    activations: 0,
  });
  updateDataSource({ mode: "sim", connectionVersion: 0 });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("SecretsPane", () => {
  it("creates a secret through the form", async () => {
    renderWithClient(<SecretsPane />);
    await openSecretsPane();
    await screen.findByText("alpha");

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "gamma" } });
    fireEvent.change(screen.getByLabelText("Value"), { target: { value: "three" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    await screen.findByText("gamma");
    expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("");
    expect((screen.getByLabelText("Value") as HTMLInputElement).value).toBe("");
  });

  it("renames a secret via inline editor", async () => {
    renderWithClient(<SecretsPane />);
    await openSecretsPane();
    await screen.findByText("alpha");
    fireEvent.click(screen.getByRole("button", { name: "Edit name alpha" }));
    const input = screen.getByLabelText("Edit name for alpha") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "" } });
    fireEvent.change(input, { target: { value: "alpha_new" } });
    fireEvent.keyDown(input, { key: "Enter" });

    await screen.findByText("alpha_new");
    expect(screen.queryByText("alpha")).not.toBeInTheDocument();
  });

  it("updates value and regenerates placeholder", async () => {
    renderWithClient(<SecretsPane />);
    await openSecretsPane();
    await screen.findByText("alpha");
    const oldPlaceholder = store.get("alpha")?.placeholder;
    fireEvent.click(screen.getByRole("button", { name: "Edit value alpha" }));
    const input = screen.getByLabelText("Edit value for alpha") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "" } });
    fireEvent.change(input, { target: { value: "updated" } });
    fireEvent.keyDown(input, { key: "Enter" });

    await waitFor(() => {
      const record = store.get("alpha");
      expect(record?.value).toBe("updated");
      expect(record?.placeholder).not.toBe(oldPlaceholder);
    });
    await screen.findByText("updated");
  });

  it("deletes a secret", async () => {
    renderWithClient(<SecretsPane />);
    await openSecretsPane();
    await screen.findByText("beta");
    fireEvent.click(screen.getByRole("button", { name: "Delete secret beta" }));

    await waitFor(() => {
      expect(screen.queryByText("beta")).not.toBeInTheDocument();
    });
  });

  it("shows validation message for invalid add", async () => {
    renderWithClient(<SecretsPane />);
    await openSecretsPane();
    await screen.findByText("alpha");

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "invalid id" } });
    fireEvent.change(screen.getByLabelText("Value"), { target: { value: "three" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    const error = await screen.findByText("invalid id");
    expect(error).toHaveClass("text-destructive");
  });

  it("displays error when rename collides", async () => {
    renderWithClient(<SecretsPane />);
    await openSecretsPane();
    await screen.findByText("alpha");
    fireEvent.click(screen.getByRole("button", { name: "Edit name alpha" }));
    const input = screen.getByLabelText("Edit name for alpha") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "" } });
    fireEvent.change(input, { target: { value: "beta" } });
    fireEvent.keyDown(input, { key: "Enter" });

    await screen.findByText("secret already exists");
  });

  it("surfaces delete failures inline", async () => {
    store.set("fail_delete", {
      id: "fail_delete",
      value: "oops",
      placeholder: generatePlaceholder(4),
      activations: 0,
    });
    renderWithClient(<SecretsPane />);
    await openSecretsPane();
    await screen.findByText("fail_delete");
    fireEvent.click(screen.getByRole("button", { name: "Delete secret fail_delete" }));

    await screen.findByText("delete failed");
  });

  it("animates rows when activation rate stays below suppression threshold", async () => {
    updateDataSource({ mode: "live", connectionVersion: 0 });
    const restoreWebSocket = installMockWebSocket();
    const baseTime = Date.parse("2024-01-01T00:00:00.000Z");
    let mockNow = baseTime;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => mockNow);

    try {
      renderWithClient(<SecretsPane defaultOpen />);

      await screen.findByText("alpha");
      await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0));
      const socket = MockWebSocket.instances[0];

      act(() => {
        const replayMessage = JSON.stringify({ event: "secret.activation", payload: { id: "alpha", activations: 1 } });
        socket.onmessage?.({ data: replayMessage } as MessageEvent);
      });
      await act(async () => {});

      mockNow = baseTime;
      for (let idx = 0; idx < 2; idx += 1) {
        mockNow = baseTime + idx * 200;
        act(() => {
          const liveMessage = JSON.stringify({
            event: "secret.activation",
            payload: { id: "alpha", activations: 2 + idx },
          });
          socket.onmessage?.({ data: liveMessage } as MessageEvent);
        });
        await act(async () => {});
      }

      await waitFor(() => {
        const row = screen.getByText("alpha").closest("tr");
        expect(row).not.toBeNull();
        expect(row?.className ?? "").toContain("animate-[flicker_0.5s_ease-out_forwards");
      });

      const toggle = screen.getByRole("button", { name: /^Secrets/ });
      const container = toggle.parentElement;
      expect(container).not.toBeNull();
      expect(container?.className ?? "").not.toContain("bg-[#7A67E6]/20 transition-colors duration-300");
    } finally {
      nowSpy.mockRestore();
      restoreWebSocket();
    }
  });

  it("suppresses activation animations when bursts exceed the threshold and recovers after the window elapses", async () => {
    updateDataSource({ mode: "live", connectionVersion: 0 });
    const restoreWebSocket = installMockWebSocket();
    const baseTime = Date.parse("2024-01-01T00:00:00.000Z");
    let mockNow = baseTime;
    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => mockNow);

    try {
      renderWithClient(<SecretsPane defaultOpen />);

      await screen.findByText("alpha");
      await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0));
      const socket = MockWebSocket.instances[0];

      act(() => {
        const replayMessage = JSON.stringify({ event: "secret.activation", payload: { id: "alpha", activations: 1 } });
        socket.onmessage?.({ data: replayMessage } as MessageEvent);
      });
      await act(async () => {});

      mockNow = baseTime;
      for (let idx = 0; idx < 5; idx += 1) {
        mockNow = baseTime + idx * 50;
        act(() => {
          const liveMessage = JSON.stringify({
            event: "secret.activation",
            payload: { id: "alpha", activations: 10 + idx },
          });
          socket.onmessage?.({ data: liveMessage } as MessageEvent);
        });
        await act(async () => {});
      }

      await waitFor(() => {
        const row = screen.getByText("alpha").closest("tr");
        expect(row).not.toBeNull();
        const className = row?.className ?? "";
        expect(className).toContain("bg-[#7A67E6]/20");
        expect(className).not.toContain("animate-[flicker_0.5s_ease-out_forwards");
      });

      await waitFor(() => {
        const container = screen.getByRole("button", { name: /^Secrets/ }).parentElement;
        expect(container).not.toBeNull();
        expect(container?.className ?? "").toContain("bg-[#7A67E6]/20 transition-colors duration-300");
      });

      mockNow = baseTime + BURST_WINDOW_MS + 50;
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, BURST_WINDOW_MS + 50));
      });

      mockNow = baseTime + BURST_WINDOW_MS + 250;
      act(() => {
        const followupMessage = JSON.stringify({
          event: "secret.activation",
          payload: { id: "alpha", activations: 42 },
        });
        socket.onmessage?.({ data: followupMessage } as MessageEvent);
      });
      await act(async () => {});

      await waitFor(() => {
        const row = screen.getByText("alpha").closest("tr");
        expect(row).not.toBeNull();
        const className = row?.className ?? "";
        expect(className).toContain("animate-[flicker_0.5s_ease-out_forwards");
      });
    } finally {
      nowSpy.mockRestore();
      restoreWebSocket();
    }
  });
});

describe("useSecretsActivationListener", () => {
  let restoreWebSocket: (() => void) | null = null;

  beforeAll(() => {
    restoreWebSocket = installMockWebSocket();
  });

  afterAll(() => {
    restoreWebSocket?.();
    restoreWebSocket = null;
  });

  beforeEach(() => {
    MockWebSocket.instances = [];
    placeholderSeed = 0;
  });

  it("updates activation counts when events arrive", async () => {
    updateDataSource({ mode: "live", connectionVersion: 0 });
    const queryClient = createQueryClient();
    queryClient.setQueryData(secretKeys.list(), [
      { id: "alpha", value: "one", placeholder: "abc", activations: 0 },
    ] satisfies SecretRecord[]);

    const wrapper = ({ children }: PropsWithChildren) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );

    const { unmount } = renderHook(() => useSecretsActivationListener(true), { wrapper });

    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0));
    const socket = MockWebSocket.instances[0];

    act(() => {
      socket.onmessage?.({ data: JSON.stringify({ event: "secret.activation", payload: { id: "alpha", activations: 5 } }) } as MessageEvent);
    });

    await waitFor(() => {
      const data = queryClient.getQueryData<SecretRecord[]>(secretKeys.list());
      expect(data?.[0]?.activations).toBe(5);
    });

    unmount();
  });

  it("ignores replay activations but animates subsequent batches", async () => {
    updateDataSource({ mode: "live", connectionVersion: 0 });
    const queryClient = createQueryClient();
    queryClient.setQueryData(secretKeys.list(), [
      { id: "alpha", value: "one", placeholder: "abc", activations: 0 },
      { id: "beta", value: "two", placeholder: "def", activations: 0 },
    ] satisfies SecretRecord[]);

    const wrapper = ({ children }: PropsWithChildren) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );

    const onActivation = vi.fn();
    const { unmount } = renderHook(() => useSecretsActivationListener(true, onActivation), { wrapper });

    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0));
    const socket = MockWebSocket.instances[0];

    act(() => {
      const replayMessage = [
        JSON.stringify({ event: "secret.activation", payload: { id: "alpha", activations: 2 } }),
        JSON.stringify({ event: "secret.activation", payload: { id: "beta", activations: 4 } }),
      ].join("\n");
      socket.onmessage?.({ data: replayMessage } as MessageEvent);
    });

    await waitFor(() => {
      const data = queryClient.getQueryData<SecretRecord[]>(secretKeys.list()) ?? [];
      expect(data.find((record) => record.id === "alpha")?.activations).toBe(2);
      expect(data.find((record) => record.id === "beta")?.activations).toBe(4);
    });
    expect(onActivation).not.toHaveBeenCalled();

    act(() => {
      const liveMessage = [
        JSON.stringify({ event: "secret.activation", payload: { id: "alpha", activations: 3 } }),
        JSON.stringify({ event: "secret.activation", payload: { id: "beta", activations: 7 } }),
      ].join("\n");
      socket.onmessage?.({ data: liveMessage } as MessageEvent);
    });

    await waitFor(() => {
      const data = queryClient.getQueryData<SecretRecord[]>(secretKeys.list()) ?? [];
      expect(data.find((record) => record.id === "alpha")?.activations).toBe(3);
      expect(data.find((record) => record.id === "beta")?.activations).toBe(7);
      expect(onActivation).toHaveBeenCalledTimes(2);
    });

    expect(onActivation).toHaveBeenNthCalledWith(1, "alpha");
    expect(onActivation).toHaveBeenNthCalledWith(2, "beta");

    unmount();
  });

  it("renders replay activations without triggering animations", async () => {
    const highlightClass = "bg-[#7A67E6]/10";

    updateDataSource({ mode: "live", connectionVersion: 0 });
    const { queryClient } = renderWithClient(<SecretsPane defaultOpen />);

    await screen.findByText("alpha");
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0));
    const socket = MockWebSocket.instances[0];

    vi.useFakeTimers();
    try {
      act(() => {
        const replayMessage = [
          JSON.stringify({ event: "secret.activation", payload: { id: "alpha", activations: 2 } }),
          JSON.stringify({ event: "secret.activation", payload: { id: "beta", activations: 4 } }),
        ].join("\n");
        socket.onmessage?.({ data: replayMessage } as MessageEvent);
      });

      await act(async () => {});

      const replayRow = screen.getByText("alpha").closest("tr");
      expect(replayRow).not.toBeNull();
      expect(replayRow?.className ?? "").not.toContain(highlightClass);

      const replayData = queryClient.getQueryData<SecretRecord[]>(secretKeys.list()) ?? [];
      expect(replayData.find((record) => record.id === "alpha")?.activations).toBe(2);
      expect(replayData.find((record) => record.id === "beta")?.activations).toBe(4);

      act(() => {
        const liveMessage = [
          JSON.stringify({ event: "secret.activation", payload: { id: "alpha", activations: 3 } }),
          JSON.stringify({ event: "secret.activation", payload: { id: "beta", activations: 7 } }),
        ].join("\n");
        socket.onmessage?.({ data: liveMessage } as MessageEvent);
      });

      await act(async () => {});

      const liveAlphaRow = screen.getByText("alpha").closest("tr");
      const liveBetaRow = screen.getByText("beta").closest("tr");
      expect(liveAlphaRow).not.toBeNull();
      expect(liveBetaRow).not.toBeNull();
      expect(liveAlphaRow?.className ?? "").toContain(highlightClass);
      expect(liveBetaRow?.className ?? "").toContain(highlightClass);

      act(() => {
        vi.runAllTimers();
      });

      await act(async () => {});

      const clearedAlphaRow = screen.getByText("alpha").closest("tr");
      const clearedBetaRow = screen.getByText("beta").closest("tr");
      expect(clearedAlphaRow).not.toBeNull();
      expect(clearedBetaRow).not.toBeNull();
      expect(clearedAlphaRow?.className ?? "").not.toContain(highlightClass);
      expect(clearedBetaRow?.className ?? "").not.toContain(highlightClass);
    } finally {
      vi.useRealTimers();
    }
  });
});
