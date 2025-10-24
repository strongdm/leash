import { act, fireEvent, render, screen } from "@testing-library/react";
import CedarEditor from "./cedar-editor";
import type { Monaco } from "@monaco-editor/react";
import type * as monacoEditor from "monaco-editor";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { usePolicyBlocksContext } from "@/lib/policy/policy-blocks-context";
import {
  fetchPolicyCompletions,
  validateCedarPolicy,
} from "@/lib/policy/api";

vi.mock("@/lib/policy/policy-blocks-context", () => ({
  usePolicyBlocksContext: vi.fn(),
}));

const mockContext = vi.mocked(usePolicyBlocksContext);

let fetchSpy: vi.MockedFunction<typeof fetchPolicyCompletions>;
let validateSpy: vi.MockedFunction<typeof validateCedarPolicy>;

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

let registeredProvider: monacoEditor.languages.CompletionItemProvider | null = null;
let currentModelValue = SAMPLE_POLICY;

const fakeModel = {
  getValue: () => currentModelValue,
};

const fakeEditor: Partial<monacoEditor.editor.IStandaloneCodeEditor> = {
  getModel: () => fakeModel as monacoEditor.editor.ITextModel,
  updateOptions: vi.fn(),
  onDidDispose: vi.fn(),
};

const fakeMonaco = {
  languages: {
    register: vi.fn(),
    setLanguageConfiguration: vi.fn(),
    setMonarchTokensProvider: vi.fn(),
    registerCompletionItemProvider: vi.fn((languageId: string, provider: monacoEditor.languages.CompletionItemProvider) => {
      registeredProvider = provider;
      return { dispose: vi.fn() } as monacoEditor.IDisposable;
    }),
    CompletionItemInsertTextRule: { InsertAsSnippet: 4 },
    CompletionItemKind: {
      Keyword: 14,
      Function: 3,
      Class: 5,
      Field: 4,
      Variable: 6,
      Snippet: 27,
      Interface: 7,
      EnumMember: 12,
      Property: 9,
      Text: 0,
    },
  },
  editor: {
    setModelMarkers: vi.fn(),
    MarkerSeverity: { Error: 8, Warning: 4 },
  },
  Range: class Range {
    constructor(
      public startLineNumber: number,
      public startColumn: number,
      public endLineNumber: number,
      public endColumn: number,
    ) {}
  },
} as unknown as Monaco;

type MockEditorProps = {
  value?: string;
  beforeMount?: (monaco: Monaco) => void;
  onMount?: (editor: monacoEditor.editor.IStandaloneCodeEditor, monaco: Monaco) => void;
  onChange?: (value: string | undefined) => void;
};

vi.mock("@monaco-editor/react", () => {
  const Component = (props: MockEditorProps) => {
    currentModelValue = props.value ?? "";
    props.beforeMount?.(fakeMonaco);
    props.onMount?.(fakeEditor as monacoEditor.editor.IStandaloneCodeEditor, fakeMonaco);
    return (
      <textarea
        data-testid="mock-editor"
        value={props.value ?? ""}
        onChange={(event) => {
          currentModelValue = event.target.value;
          props.onChange?.(event.target.value);
        }}
      />
    );
  };
  return { default: Component };
});

vi.mock("@/lib/policy/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/policy/api")>("@/lib/policy/api");
  return {
    ...actual,
    fetchPolicyCompletions: vi.fn(),
    validateCedarPolicy: vi.fn(),
  };
});

function createCancellationToken(): monacoEditor.CancellationToken {
  return {
    isCancellationRequested: false,
    onCancellationRequested: () => ({ dispose: vi.fn() }),
  } as unknown as monacoEditor.CancellationToken;
}

describe("CedarEditor", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    registeredProvider = null;
    currentModelValue = SAMPLE_POLICY;

    fetchSpy = vi.mocked(fetchPolicyCompletions);
    fetchSpy.mockResolvedValue({
      items: [
        {
          label: 'Action::"FileOpen"',
          kind: "action",
          insertText: 'Action::"FileOpen"',
          detail: "Allow reading or writing files",
          documentation: "Applies to file open operations.",
          range: {
            start: { line: 1, column: 1 },
            end: { line: 1, column: 1 },
          },
        },
      ],
    });

    validateSpy = vi.mocked(validateCedarPolicy);
    validateSpy.mockResolvedValue({
      allowAllConnect: true,
      allowConnect: 1,
      denyConnect: 0,
      issues: [
        {
          policyId: "Policy::Example",
          severity: "error",
          code: "unsupported_action",
          message: "Action not supported",
        },
      ],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("updates editor draft when user types", () => {
    const context = createContext();
    mockContext.mockReturnValue(context);

    render(<CedarEditor />);

    const textarea = screen.getByTestId("mock-editor") as HTMLTextAreaElement;
    fireEvent.change(textarea, { target: { value: "permit (principal, action, resource);" } });

    expect(context.setEditorDraft).toHaveBeenCalledWith("permit (principal, action, resource);");
  });

  test("registers completion provider and shows suggestion help", async () => {
    mockContext.mockReturnValue(createContext());

    render(<CedarEditor />);

    await act(async () => {
      await Promise.resolve();
    });

    expect(fakeMonaco.languages.registerCompletionItemProvider).toHaveBeenCalledWith(
      "cedar",
      expect.any(Object),
    );

    const provider = registeredProvider;
    expect(provider).not.toBeNull();

    let result: monacoEditor.languages.CompletionList | undefined;
    await act(async () => {
      result = await provider!.provideCompletionItems(
        fakeModel as monacoEditor.editor.ITextModel,
        { lineNumber: 1, column: 1 },
        {} as monacoEditor.languages.CompletionContext,
        createCancellationToken(),
      );
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        cedar: SAMPLE_POLICY,
        cursor: { line: 1, column: 1 },
      }),
      expect.any(AbortSignal),
    );
    expect(result?.suggestions?.length ?? 0).toBeGreaterThan(0);
  });

  test("applies validation markers", async () => {
    mockContext.mockReturnValue(createContext());

    render(<CedarEditor />);

    await act(async () => {
      await Promise.resolve();
    });

    await act(async () => {
      vi.runOnlyPendingTimers();
      await Promise.resolve();
    });

    expect(validateSpy).toHaveBeenCalled();
    expect(fakeMonaco.editor.setModelMarkers).toHaveBeenCalled();
  });
});
