export type PolicyCategory =
  | "Networking"
  | "Packages"
  | "Dependencies"
  | "AI Services"
  | "Filesystem"
  | "Processes"
  | "Secrets";

export type PolicyEffect = "allow" | "deny";

export type PolicySource = "active" | "runtime" | "file";

export type PolicyBlock = {
  id: string;
  title: string; // LLM-style summary
  description: string; // short supporting text
  category: PolicyCategory;
  effect: PolicyEffect; // allowed or denied
  cedar: string; // underlying Cedar policy snippet (read-only)
  // internal fields (for UI coherence with backend layers)
  source?: PolicySource; // which layer this block originated from
  ruleKey?: string; // stable key of the underlying rule for diffing
  lastUpdated: number; // epoch ms
  instancesMatched: number; // simulated instances under scope
  activityScore: number; // 0..100 for blinkenlights
};
