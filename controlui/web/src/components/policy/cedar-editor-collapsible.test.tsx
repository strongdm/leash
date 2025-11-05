import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, test, vi } from "vitest";
import CedarEditorCollapsible from "./cedar-editor-collapsible";
import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";

vi.mock("@/lib/policy/policy-blocks-context", () => ({
  usePolicyBlocksContext: vi.fn(),
}));

vi.mock("@/components/policy/cedar-editor", () => ({
  __esModule: true,
  default: () => <div data-testid="cedar-editor" />,
}));

const mockContext = vi.mocked(usePolicyBlocksContext);

type ContextStub = {
  submitError: string | null;
  cedarRuntime: string;
  cedarFile: string;
  cedarBaseline: string;
  editorDraft: string;
};

function createContext(overrides: Partial<ContextStub> = {}): ContextStub {
  const defaults: ContextStub = {
    submitError: null,
    cedarRuntime: "",
    cedarFile: "",
    cedarBaseline: "",
    editorDraft: "",
  };
  return { ...defaults, ...overrides };
}

describe("CedarEditorCollapsible keyboard shortcut", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockContext.mockReturnValue(createContext());
  });

  test("toggles the editor when Ctrl+Alt+E is pressed", () => {
    render(<CedarEditorCollapsible />);

    expect(screen.queryByTestId("cedar-editor")).toBeNull();

    fireEvent.keyDown(window, { key: "e", ctrlKey: true, altKey: true });
    expect(screen.getByTestId("cedar-editor")).toBeInTheDocument();

    fireEvent.keyDown(window, { key: "e", ctrlKey: true, altKey: true });
    expect(screen.queryByTestId("cedar-editor")).toBeNull();
  });

  test("toggles the editor when Cmd+Ctrl+E is pressed", () => {
    render(<CedarEditorCollapsible />);

    expect(screen.queryByTestId("cedar-editor")).toBeNull();

    fireEvent.keyDown(window, { key: "e", metaKey: true, ctrlKey: true });
    expect(screen.getByTestId("cedar-editor")).toBeInTheDocument();

    fireEvent.keyDown(window, { key: "e", metaKey: true, ctrlKey: true });
    expect(screen.queryByTestId("cedar-editor")).toBeNull();
  });
});
