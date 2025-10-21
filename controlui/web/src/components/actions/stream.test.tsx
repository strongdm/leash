import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SimulationState } from "@/lib/mock/types";
import { ActionsStream } from "@/components/actions/stream";

const mockState: SimulationState = {
  instances: new Map(),
  recentActions: [],
  totals: {
    actionsLast60s: Array.from({ length: 60 }, () => 0),
    deniedLast60s: Array.from({ length: 60 }, () => 0),
    cursor: 0,
  },
};

vi.mock("@/lib/mock/sim", () => ({
  useSimulation: () => mockState,
}));

vi.mock("@/lib/policy/policy-blocks-context", () => ({
  usePolicyBlocksContext: () => ({
    refresh: vi.fn(),
    patchPolicies: vi.fn().mockResolvedValue(true),
  }),
}));

vi.mock("@/lib/time", () => ({
  timeAgo: () => "just now",
}));

describe("ActionsStream", () => {
  beforeEach(() => {
    mockState.recentActions = [];
  });

  it("renders aggregated event counts and summary totals", () => {
    mockState.recentActions = [
      {
        id: "recent-older",
        instanceId: "instance-1",
        type: "net/connect",
        name: "api.openai.com",
        ts: 1,
        allowed: false,
        repeatCount: 2,
      },
      {
        id: "recent-newest",
        instanceId: "instance-1",
        type: "file/open",
        name: "/dev/tty",
        ts: 2,
        allowed: true,
        repeatCount: 3,
      },
    ];

    render(<ActionsStream />);

    const table = screen.getByRole("table");
    const dataRows = within(table).getAllByRole("row").slice(1);
    expect(dataRows).toHaveLength(2);

    const fileRow = dataRows.find((row) => within(row).queryByText("file/open"));
    expect(fileRow).toBeDefined();
    if (!fileRow) throw new Error("missing file/open row");
    const badge = within(fileRow).getByTestId("repeat-count");
    expect(badge).toHaveTextContent("3");
    expect(badge).toBeInTheDocument();

    expect(screen.getByText("Total: 5")).toBeInTheDocument();
    expect(screen.getByText("Allowed: 3")).toBeInTheDocument();
    expect(screen.getByText("Denied: 2")).toBeInTheDocument();
    expect(screen.getByText("2 shown")).toBeInTheDocument();
  });

  it("scrolls a page down when space is pressed while hovered", () => {
    render(<ActionsStream />);

    const scrollArea = screen.getByTestId("actions-scroll-area") as HTMLDivElement;
    const scrollBy = vi.fn();
    Object.defineProperty(scrollArea, "clientHeight", { value: 320, configurable: true });
    Object.defineProperty(scrollArea, "scrollTop", { value: 0, writable: true });
    (scrollArea as unknown as { scrollBy: typeof window.scrollBy }).scrollBy = scrollBy as unknown as typeof window.scrollBy;

    fireEvent.mouseEnter(scrollArea);
    fireEvent.keyDown(window, { key: " ", shiftKey: false });

    expect(scrollBy).toHaveBeenCalledWith({ top: 320, behavior: "smooth" });
  });

  it("scrolls a page up when shift+space is pressed while hovered", () => {
    render(<ActionsStream />);

    const scrollArea = screen.getByTestId("actions-scroll-area") as HTMLDivElement;
    const scrollBy = vi.fn();
    Object.defineProperty(scrollArea, "clientHeight", { value: 200, configurable: true });
    Object.defineProperty(scrollArea, "scrollTop", { value: 0, writable: true });
    (scrollArea as unknown as { scrollBy: typeof window.scrollBy }).scrollBy = scrollBy as unknown as typeof window.scrollBy;

    fireEvent.mouseEnter(scrollArea);
    fireEvent.keyDown(window, { key: " ", shiftKey: true });

    expect(scrollBy).toHaveBeenCalledWith({ top: -200, behavior: "smooth" });
  });

  it("does not scroll when space is pressed outside the hover area", () => {
    render(<ActionsStream />);

    const scrollArea = screen.getByTestId("actions-scroll-area") as HTMLDivElement;
    const scrollBy = vi.fn();
    Object.defineProperty(scrollArea, "clientHeight", { value: 150, configurable: true });
    Object.defineProperty(scrollArea, "scrollTop", { value: 0, writable: true });
    (scrollArea as unknown as { scrollBy: typeof window.scrollBy }).scrollBy = scrollBy as unknown as typeof window.scrollBy;

    fireEvent.keyDown(window, { key: " " });

    expect(scrollBy).not.toHaveBeenCalled();
  });

  it("exposes a native scrollbar gutter on the scroll container", () => {
    render(<ActionsStream />);

    const scrollArea = screen.getByTestId("actions-scroll-area") as HTMLDivElement;
    expect(scrollArea.className).toContain("overflow-y-auto");
    expect(scrollArea.style.scrollbarGutter).toBe("stable");
  });

  it("includes project slug and total event count in the download filename", () => {
    mockState.recentActions = [
      {
        id: "alpha",
        instanceId: "instance-1",
        type: "proc/exec",
        name: "ls",
        ts: 1,
        allowed: true,
        repeatCount: 2,
      },
      {
        id: "beta",
        instanceId: "instance-2",
        type: "net/connect",
        name: "api.service.local",
        ts: 2,
        allowed: false,
        repeatCount: 1,
      },
    ];

    const leashWindow = window as typeof window & { __LEASH_TITLE_TEXT?: string };
    leashWindow.__LEASH_TITLE_TEXT = "Leash | DTU Project > build";

    const originalCreate = URL.createObjectURL;
    const originalRevoke = URL.revokeObjectURL;
    const createObjectURLMock = vi.fn(() => "blob:mock");
    const revokeObjectURLMock = vi.fn();
    (URL as unknown as { createObjectURL: typeof createObjectURLMock }).createObjectURL = createObjectURLMock;
    (URL as unknown as { revokeObjectURL: typeof revokeObjectURLMock }).revokeObjectURL = revokeObjectURLMock;

    const appendChildSpy = vi.spyOn(document.body, "appendChild");
    const removeChildSpy = vi.spyOn(document.body, "removeChild");
    const anchorClickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    vi.useFakeTimers();

    try {
      render(<ActionsStream />);
      const button = screen.getByRole("button", { name: /download events/i });
      fireEvent.click(button);

      expect(createObjectURLMock).toHaveBeenCalled();
      const anchorsAppended = appendChildSpy.mock.calls
        .map(([node]) => node as HTMLElement)
        .filter((node) => node.tagName === "A");
      expect(anchorsAppended).not.toHaveLength(0);
      const anchor = anchorsAppended[anchorsAppended.length - 1] as HTMLAnchorElement;
      expect(anchor.download).toMatch(/^leash-dtu-project-3-events-/);
      act(() => {
        vi.runAllTimers();
      });
      expect(revokeObjectURLMock).toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
      appendChildSpy.mockRestore();
      removeChildSpy.mockRestore();
      anchorClickSpy.mockRestore();
      delete leashWindow.__LEASH_TITLE_TEXT;
      (URL as unknown as { createObjectURL?: typeof createObjectURLMock }).createObjectURL = originalCreate;
      (URL as unknown as { revokeObjectURL?: typeof revokeObjectURLMock }).revokeObjectURL = originalRevoke;
    }
  });

  it("downloads when the keyboard shortcut is pressed", () => {
    mockState.recentActions = [
      {
        id: "shortcut-1",
        instanceId: "instance-1",
        type: "proc/exec",
        name: "ls",
        ts: 1,
        allowed: true,
        repeatCount: 1,
      },
    ];

    const originalCreate = URL.createObjectURL;
    const originalRevoke = URL.revokeObjectURL;
    const createObjectURLMock = vi.fn(() => "blob:mock");
    const revokeObjectURLMock = vi.fn();
    (URL as unknown as { createObjectURL: typeof createObjectURLMock }).createObjectURL = createObjectURLMock;
    (URL as unknown as { revokeObjectURL: typeof revokeObjectURLMock }).revokeObjectURL = revokeObjectURLMock;

    const appendChildSpy = vi.spyOn(document.body, "appendChild");
    const removeChildSpy = vi.spyOn(document.body, "removeChild");
    const anchorClickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    vi.useFakeTimers();

    try {
      render(<ActionsStream />);
      fireEvent.keyDown(window, { key: "d", ctrlKey: true, altKey: true });

      expect(createObjectURLMock).toHaveBeenCalled();
      expect(appendChildSpy).toHaveBeenCalled();
      act(() => {
        vi.runAllTimers();
      });
      expect(revokeObjectURLMock).toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
      appendChildSpy.mockRestore();
      removeChildSpy.mockRestore();
      anchorClickSpy.mockRestore();
      (URL as unknown as { createObjectURL?: typeof createObjectURLMock }).createObjectURL = originalCreate;
      (URL as unknown as { revokeObjectURL?: typeof revokeObjectURLMock }).revokeObjectURL = originalRevoke;
    }
  });
});
