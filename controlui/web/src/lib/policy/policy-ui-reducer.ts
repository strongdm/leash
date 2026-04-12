export type PolicyUIState = {
  editorDraft: string;
  notice: string | null;
};

export type PolicyUIAction =
  | { type: "SET_DRAFT"; payload: string }
  | { type: "SHOW_NOTICE"; payload: string }
  | { type: "CLEAR_NOTICE" }
  | { type: "INIT_DRAFT"; payload: string };

export const initialPolicyUIState: PolicyUIState = {
  editorDraft: "",
  notice: null,
};

export function policyUIReducer(
  state: PolicyUIState,
  action: PolicyUIAction
): PolicyUIState {
  switch (action.type) {
    case "SET_DRAFT":
      return { ...state, editorDraft: action.payload };

    case "SHOW_NOTICE":
      return { ...state, notice: action.payload };

    case "CLEAR_NOTICE":
      return { ...state, notice: null };

    case "INIT_DRAFT":
      if (state.editorDraft.trim() === "") {
        return { ...state, editorDraft: action.payload };
      }
      return state;

    default:
      return state;
  }
}
