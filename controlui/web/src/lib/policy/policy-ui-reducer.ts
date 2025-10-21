/**
 * UI State Reducer for Policy Management
 *
 * Handles local UI state only - server state is managed by React Query.
 * This ensures unidirectional data flow and prevents sync issues.
 */

export type PolicyUIState = {
  editorDraft: string;
  editorOpen: boolean;
  notice: string | null;
};

export type PolicyUIAction =
  | { type: "SET_DRAFT"; payload: string }
  | { type: "TOGGLE_EDITOR" }
  | { type: "OPEN_EDITOR" }
  | { type: "CLOSE_EDITOR" }
  | { type: "SHOW_NOTICE"; payload: string }
  | { type: "CLEAR_NOTICE" }
  | { type: "INIT_DRAFT"; payload: string };

export const initialPolicyUIState: PolicyUIState = {
  editorDraft: "",
  editorOpen: false,
  notice: null,
};

export function policyUIReducer(
  state: PolicyUIState,
  action: PolicyUIAction
): PolicyUIState {
  switch (action.type) {
    case "SET_DRAFT":
      return { ...state, editorDraft: action.payload };

    case "TOGGLE_EDITOR":
      return { ...state, editorOpen: !state.editorOpen };

    case "OPEN_EDITOR":
      return { ...state, editorOpen: true };

    case "CLOSE_EDITOR":
      return { ...state, editorOpen: false };

    case "SHOW_NOTICE":
      return { ...state, notice: action.payload };

    case "CLEAR_NOTICE":
      return { ...state, notice: null };

    case "INIT_DRAFT":
      // Only initialize if draft is empty
      if (state.editorDraft.trim() === "") {
        return { ...state, editorDraft: action.payload };
      }
      return state;

    default:
      return state;
  }
}
