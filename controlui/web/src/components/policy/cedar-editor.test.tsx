import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import CedarEditor from "./cedar-editor";
import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";
import { validateCedarPolicy } from "@/lib/policy/api";

vi.mock("@/lib/policy/policy-blocks-context", () => ({
  usePolicyBlocksContext: vi.fn(),
}));

vi.mock("@/lib/policy/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/policy/api")>("@/lib/policy/api");
  return {
    ...actual,
    fetchPolicyCompletions: vi.fn(),
    validateCedarPolicy: vi.fn(),
  };
});

const mockContext = vi.mocked(usePolicyBlocksContext);
let validateSpy: ReturnType<typeof vi.mocked<typeof validateCedarPolicy>>;

const SAMPLE_POLICY = 'permit (principal, action == Action::"FileOpen", resource);';

type CedarEditorContextStub = {
  cedarRuntime: string;
  cedarFile: string;
  cedarBaseline: string;
  submitting: boolean;
  submitError: string | null;
  persistCedar: (cedar?: string, force?: boolean) => Promise<boolean>;
  applyEnforce: () => Promise<boolean>;
  enforcementMode: "enforce" | "permit-all";
  editorDraft: string;
  setEditorDraft: (value: string) => void;
  showNotice: (message: string) => void;
  notice: string | null;
};

function createContext(overrides: Partial<CedarEditorContextStub> = {}): CedarEditorContextStub {
  const defaults: CedarEditorContextStub = {
    cedarRuntime: "",
    cedarFile: "",
    cedarBaseline: "",
    submitting: false,
    submitError: null,
    persistCedar: vi.fn(async () => true),
    applyEnforce: vi.fn(async () => true),
    enforcementMode: "enforce",
    editorDraft: SAMPLE_POLICY,
    setEditorDraft: vi.fn(),
    showNotice: vi.fn(),
    notice: null,
  };
  return { ...defaults, ...overrides };
}

describe("CedarEditor", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();

    validateSpy = vi.mocked(validateCedarPolicy);
    validateSpy.mockResolvedValue({
      allowAllConnect: true,
      allowOpen: 0,
      allowExec: 0,
      allowConnect: 1,
      denyOpen: 0,
      denyExec: 0,
      denyConnect: 0,
      issues: [],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("renders the editor with current draft", () => {
    mockContext.mockReturnValue(createContext());
    render(<CedarEditor />);

    const textarea = screen.getByRole("textbox");
    expect(textarea).toHaveValue(SAMPLE_POLICY);
  });

  test("calls setEditorDraft when user types", () => {
    const context = createContext();
    mockContext.mockReturnValue(context);
    render(<CedarEditor />);

    const textarea = screen.getByRole("textbox");
    fireEvent.change(textarea, { target: { value: "permit (principal, action, resource);" } });

    expect(context.setEditorDraft).toHaveBeenCalledWith("permit (principal, action, resource);");
  });

  test("debounces validation after draft change", async () => {
    mockContext.mockReturnValue(createContext());
    render(<CedarEditor />);

    // Validation hasn't fired yet
    expect(validateSpy).not.toHaveBeenCalled();

    // Advance past the debounce
    await vi.advanceTimersByTimeAsync(600);

    expect(validateSpy).toHaveBeenCalledWith(SAMPLE_POLICY, expect.any(AbortSignal));
  });
});
