import { render, waitFor, screen } from "@testing-library/react";
import CedarEditor from "./cedar-editor";
import type { HLJSApi } from "highlight.js";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { loadCedarHighlighter } from "@/lib/highlighting";
import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";

vi.mock("@/lib/policy/policy-blocks-context", () => ({
  usePolicyBlocksContext: vi.fn(),
}));

vi.mock("@/lib/highlighting", () => ({
  loadCedarHighlighter: vi.fn(),
}));

vi.mock("@/lib/policy/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/policy/api")>("@/lib/policy/api");
  return {
    ...actual,
    validateCedarPolicy: vi.fn(async () => ({
      allowAllConnect: true,
      allowConnect: 1,
      denyConnect: 0,
      issues: [],
    })),
  };
});

const mockContext = vi.mocked(usePolicyBlocksContext);
const mockLoader = vi.mocked(loadCedarHighlighter);

const SAMPLE_POLICY = 'permit (principal, action, resource);';

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
    persistCedar: vi.fn<(cedar?: string, force?: boolean) => Promise<boolean>>(async () => true),
    applyEnforce: vi.fn<[], Promise<boolean>>(async () => true),
    enforcementMode: "enforce",
    editorDraft: SAMPLE_POLICY,
    setEditorDraft: vi.fn<(value: string) => void>(),
    showNotice: vi.fn<(message: string) => void>(),
    notice: null,
  };
  return { ...defaults, ...overrides };
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  mockLoader.mockReset();
});

test("highlights cedar keywords once the highlighter loads", async () => {
  mockContext.mockReturnValue(createContext());
  const highlightMock = vi.fn(() => ({
    value: '<span class="hljs-keyword">permit</span> resource',
  }));
  mockLoader.mockResolvedValue({
    highlight: highlightMock,
  } as unknown as HLJSApi);

  render(<CedarEditor />);

  await waitFor(() => expect(highlightMock).toHaveBeenCalled());
  const highlighted = document.querySelectorAll(".hljs-keyword");
  expect(highlighted.length).toBeGreaterThan(0);
  expect(highlighted[0]?.textContent).toBe("permit");
});

test("escapes HTML if the highlighter throws", async () => {
  const sample = '<script>alert("x")</script>';
  mockContext.mockReturnValue(
    createContext({
      editorDraft: sample,
    }),
  );
  mockLoader.mockResolvedValue({
    highlight: vi.fn(() => {
      throw new Error("boom");
    }),
  } as unknown as HLJSApi);

  render(<CedarEditor />);

  await waitFor(() => {
    expect(mockLoader).toHaveBeenCalled();
  });
  const textarea = screen.getByDisplayValue(sample) as HTMLTextAreaElement;
  expect(textarea).toBeDefined();
  const codeLayer = document.querySelector(".cedar-highlight pre");
  expect(codeLayer).not.toBeNull();
  expect(codeLayer?.innerHTML ?? "").toContain("&lt;script&gt;");
  expect(document.querySelector(".cedar-highlight script")).toBeNull();
});
