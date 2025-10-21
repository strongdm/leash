import type { HLJSApi } from "highlight.js";

let hljsPromise: Promise<HLJSApi> | null = null;

export async function loadCedarHighlighter(): Promise<HLJSApi> {
  if (!hljsPromise) {
    hljsPromise = import("highlight.js/lib/core").then(async (mod) => {
      const hljs = mod.default as HLJSApi;
      const { registerCedarLanguages } = await import("./cedar");
      registerCedarLanguages(hljs);
      return hljs;
    });
  }
  return hljsPromise;
}
