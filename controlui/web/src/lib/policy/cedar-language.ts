import Prism from "prismjs";

export const CEDAR_LANGUAGE_ID = "cedar";

/**
 * Register a lightweight Prism grammar for the Cedar policy language.
 * Called once before the editor mounts.
 */
export function ensureCedarLanguage() {
  if (Prism.languages[CEDAR_LANGUAGE_ID]) {
    return;
  }

  Prism.languages[CEDAR_LANGUAGE_ID] = {
    comment: [
      { pattern: /\/\/.*/, greedy: true },
      { pattern: /\/\*[\s\S]*?\*\//, greedy: true },
    ],
    entity: {
      pattern: /\w[\w.]*::"[^"]*"/,
      greedy: true,
    },
    keyword: /\b(?:permit|forbid|when|unless|principal|action|resource|context|in|like|if|then|else|has)\b/,
    string: { pattern: /"(?:[^"\\]|\\.)*"/, greedy: true },
    number: /\b\d+\b/,
    operator: /==|!=|&&|\|\||<=|>=|<|>/,
    punctuation: /[{}[\]();,]/,
  };
}

/**
 * Highlight Cedar code using the registered Prism grammar.
 * Returns an HTML string for use with react-simple-code-editor.
 */
export function highlightCedar(code: string): string {
  ensureCedarLanguage();
  return Prism.highlight(code, Prism.languages[CEDAR_LANGUAGE_ID], CEDAR_LANGUAGE_ID);
}
