import type { Monaco } from "@monaco-editor/react";

export const CEDAR_LANGUAGE_ID = "cedar";

let languageRegistered = false;

export function ensureCedarLanguage(monaco: Monaco) {
  if (languageRegistered) {
    return;
  }

  monaco.languages.register({ id: CEDAR_LANGUAGE_ID });

  monaco.languages.setLanguageConfiguration(CEDAR_LANGUAGE_ID, {
    comments: {
      lineComment: "//",
      blockComment: ["/*", "*/"],
    },
    brackets: [
      ["{", "}"],
      ["[", "]"],
      ["(", ")"],
    ],
    autoClosingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"', notIn: ["string"] },
    ],
    surroundingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"' },
    ],
    wordPattern: /(-?\d*\.?\d\w*)|[^\s\(\)\{\}\[\],;]+/g,
    indentationRules: {
      increaseIndentPattern: /^.*\{[^}]*$/,
      decreaseIndentPattern: /^\s*\}/,
    },
  });

  monaco.languages.setMonarchTokensProvider(CEDAR_LANGUAGE_ID, {
    defaultToken: "",
    tokenPostfix: ".cedar",
    brackets: [
      { open: "{", close: "}", token: "delimiter.curly" },
      { open: "[", close: "]", token: "delimiter.square" },
      { open: "(", close: ")", token: "delimiter.parenthesis" },
    ],
    keywords: ["permit", "forbid", "when", "unless", "in", "like", "and", "or"],
    operators: ["==", "!=", "in", "like", "and", "or"],
    symbols: /[=><!~?:&|+\-*\/\^%]+/,
    tokenizer: {
      root: [
        { include: "@whitespace" },
        [/[(){}\[\]]/, "@brackets"],
        [/@symbols/, "operator"],
        [/Action::"[^"]*"/, "type"],
        [/File::"[^"]*"/, "type"],
        [/Dir::"[^"]*"/, "type"],
        [/Host::"[^"]*"/, "type"],
        [/Net::DnsZone::"[^"]*"/, "type"],
        [/MCP::Server::"[^"]*"/, "type"],
        [/MCP::Tool::"[^"]*"/, "type"],
        [/context\.(hostname|header|value)/, "predefined"],
        [/[a-zA-Z_][\w\.:]*/, {
          cases: {
            "@keywords": "keyword",
            "@default": "identifier",
          },
        }],
        [/"([^"\\]|\\.)*$/, "string.invalid"],
        [/"/, { token: "string", next: "@string" }],
        [/\d+/, "number"],
      ],
      whitespace: [
        [/[ \t\r\n]+/, "white"],
        [/\/\*/, "comment", "@comment"],
        [/\/\/.*/, "comment"],
      ],
      comment: [
        [/[^\/*]+/, "comment"],
        [/\*\//, "comment", "@pop"],
        [/[/\*]/, "comment"],
      ],
      string: [
        [/[^\\"]+/, "string"],
        [/\\./, "string.escape"],
        [/"/, { token: "string", next: "@pop" }],
      ],
    },
  });

  languageRegistered = true;
}
