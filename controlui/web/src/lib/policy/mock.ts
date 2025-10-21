import { faker } from "@faker-js/faker";
import { PolicyBlock, PolicyCategory, PolicyEffect } from "./types";

function id(prefix: string) { return `${prefix}-${faker.string.alphanumeric(6).toLowerCase()}`; }

const blocksCatalog: Array<{
  title: string;
  description: string;
  category: PolicyCategory;
  effect: PolicyEffect;
  cedar: string;
}> = [
  {
    title: "Can download and install OS packages",
    description: "Allows apt/yum/dnf to fetch and install packages from official mirrors.",
    category: "Packages",
    effect: "allow",
    cedar: `permit(principal, action, resource) when {
  action in ["os:apt_update", "os:apt_install", "os:yum_install", "os:dnf_install"] &&
  resource in Package &&
  context.repo in ["ubuntu:official", "debian:official", "centos:official"]
};`,
  },
  {
    title: "Can download code dependencies from public registries",
    description: "Allows npm/pip/go to resolve and download public dependencies.",
    category: "Dependencies",
    effect: "allow",
    cedar: `permit(principal, action, resource) when {
  action in ["pkg:npm_install", "pkg:pip_install", "pkg:go_get"] &&
  resource in Dependency &&
  context.registry in ["npmjs.com", "pypi.org", "proxy.golang.org"]
};`,
  },
  {
    title: "Can communicate with OpenAI",
    description: "Allows outbound HTTPS to *.openai.com:443.",
    category: "AI Services",
    effect: "allow",
    cedar: `permit(principal, action, resource) when {
  action == "net:connect" &&
  resource is Host &&
  resource.port == 443 &&
  resource.hostname.endsWith("openai.com")
};`,
  },
  {
    title: "Cannot access internal metadata services",
    description: "Denies AWS/Azure/GCP instance metadata endpoints.",
    category: "Networking",
    effect: "deny",
    cedar: `forbid(principal, action, resource) when {
  action == "net:connect" && resource is Host &&
  resource.ip in ["169.254.169.254", "169.254.169.250"]
};`,
  },
  {
    title: "Cannot read SSH private keys",
    description: "Denies read access to typical private key paths.",
    category: "Secrets",
    effect: "deny",
    cedar: `forbid(principal, action, resource) when {
  action == "fs:read" && resource is File &&
  resource.path.matches("/home/*/.ssh/id_*" )
};`,
  },
  {
    title: "Can execute local tools",
    description: "Allows running common developer CLIs.",
    category: "Processes",
    effect: "allow",
    cedar: `permit(principal, action, resource) when {
  action == "proc:exec" && resource in Process &&
  resource.name in ["git", "make", "node", "python", "go"]
};`,
  },
  {
    title: "Cannot connect to arbitrary databases",
    description: "Denies outbound connections to TCP ports 5432/3306/1433 outside allowlist.",
    category: "Networking",
    effect: "deny",
    cedar: `forbid(principal, action, resource) when {
  action == "net:connect" && resource is Host &&
  resource.port in [5432, 3306, 1433] &&
  !(resource.hostname in context.dbAllowlist)
};`,
  },
  {
    title: "Can write under /workspace",
    description: "Allows write access to a dedicated working directory.",
    category: "Filesystem",
    effect: "allow",
    cedar: `permit(principal, action, resource) when {
  action in ["fs:write", "fs:create", "fs:delete"] &&
  resource is File &&
  resource.path.startsWith("/workspace/")
};`,
  },
];

export function getMockPolicyBlocks(): PolicyBlock[] {
  const now = Date.now();
  return blocksCatalog.map((b) => ({
    id: id("pol"),
    title: b.title,
    description: b.description,
    category: b.category,
    effect: b.effect,
    cedar: b.cedar,
    source: "active",
    ruleKey: id("rk"),
    lastUpdated: now - faker.number.int({ min: 60_000, max: 3600_000 }),
    instancesMatched: faker.number.int({ min: 3, max: 24 }),
    activityScore: faker.number.int({ min: 5, max: 100 }),
  }));
}
