# Leash Cedar Policy Reference (Consolidated)

Leash loads the initial access‑control policy from `/cfg/leash.cedar`. At startup
the daemon validates Cedar, transpiles it to Leash IR in memory, and loads the
resulting rules into the eBPF LSM programs and the HTTP MITM proxy.

This is the single, authoritative reference for authoring Cedar policies in Leash.
All examples use Cedar’s standard Action entity with PascalCase identifiers. No
other action namespace is accepted in documentation or generated output.

## Quick Start

Leash starts with a permissive Cedar policy so you can experiment immediately. Customize enforcement either through the Control UI (`http://localhost:18080/policies`) or the HTTP API:

```bash
curl -sS -X POST \
  -H 'Content-Type: text/plain' \
  --data-binary @./my-policy-file.cedar \
  http://localhost:18080/api/policies
```

## Statement Anatomy

Every policy statement grants (`permit`) or denies (`forbid`) a combination of
action + resource. Optional `when` clauses narrow the match using contextual
conditions.

```cedar
permit (
    principal,
    action == Action::"FileOpen",
    resource
) when {
    resource in [ Dir::"/workspace" ]
};
```

Key elements:

- **effect** – `permit` or `forbid`.
- **action** – a Cedar `Action::"PascalCase"` identifier such as `FileOpen`, `ProcessExec`, `NetworkConnect`, or `HttpRewrite`.
- **resource** – entity describing what is touched (e.g. `Dir::"/path"`, `File::"/file"`,
  `Host::"example.com"`).
- **conditions** – optional `when { ... }` block that constrains matches. Leash
  uses it primarily for HTTP rewrite header/value matching.

Statements are evaluated in the order they appear. The first matching rule
(deciding `permit` or `forbid`) wins.

### Supported Actions and Resources

| Action                            | Typical Resources                                | Notes |
| --------------------------------- | ------------------------------------------------ | ----- |
| `Action::"FileOpen"` / `Action::"FileOpenReadOnly"` / `Action::"FileOpenReadWrite"` | `Dir::"/path/"`, `File::"/path"` | Directories must end with `/` to include contents. |
| `Action::"ProcessExec"`          | `Dir::"/path/"`, `File::"/path"`                    | Path‑only matching; argument filtering not yet available. |
| `Action::"NetworkConnect"`       | `Host::"example.com"`, `Host::"*.domain"`, `Host::"ip:port"` | Wildcard hosts support a leading `*.` only. Ports optional. |
| `Action::"HttpRewrite"`          | `Host::"example.com"`                               | Requires `context.header` and `context.value`. |
| `Action::"McpCall"`              | `MCP::Server::"host"`, `MCP::Tool::"tool-name"`     | V1: `forbid` enforced; `permit` informational only. |

### Action→IR Mapping

Leash IR and logs use stable operation strings. Actions map as follows:

- `Action::"FileOpen"` → `file.open`
- `Action::"FileOpenReadOnly"` → `file.open:ro`
- `Action::"FileOpenReadWrite"` → `file.open:rw`
- `Action::"ProcessExec"` → `proc.exec`
- `Action::"NetworkConnect"` → `net.send`
- `Action::"HttpRewrite"` → `http.rewrite`
- `Action::"McpCall"` → `mcp.*` (MCP policy rules)

Notes:
- Directory resources must end with `/`. The transpiler normalises this; the linter warns when missing.
- IPv6 literals and CIDR are not supported in v1 policies.
- Hostname rules require the Leash proxy for hostname enforcement (kernel enforces IP only).

## File Access Examples

Permit read/write access under `/var/app/` but deny writes to `/var/app/secrets/`:

```cedar
permit (
    principal,
    action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"],
    resource
) when {
  resource in [ Dir::"/var/app/" ]
};

forbid (
    principal,
    action == Action::"FileOpenReadWrite",
    resource
) when {
  resource in [ Dir::"/var/app/secrets/" ]
};
```

Read-only access to `/etc` and `/usr/share`:

```cedar
permit (
    principal,
    action in [Action::"FileOpen", Action::"FileOpenReadOnly"],
    resource
) when {
  resource in [ Dir::"/etc/" , Dir::"/usr/share/" ]
};
```

## Process Execution Examples

Allow tools from standard locations while forbidding a specific binary:

```cedar
permit (
    principal,
    action == Action::"ProcessExec",
    resource
) when {
  resource in [ Dir::"/bin/", Dir::"/usr/bin/", Dir::"/usr/local/bin/" ]
};

forbid (
    principal,
    action == Action::"ProcessExec",
    resource
) when {
    resource in [ File::"/usr/bin/nmap" ]
};
```

Currently Cedar policies match by executable path only; argument-level filtering
still requires IR-era deny rules and is on the roadmap for a future Cedar
extension.

## Network Connectivity Examples

Permit access to trusted APIs and block social media:

```cedar
permit (
    principal,
    action == Action::"NetworkConnect",
    resource
) when {
  resource in [ Host::"api.internal" , Host::"*.corp.example" ]
};

forbid (
    principal,
    action == Action::"NetworkConnect",
    resource
) when {
    resource in [ Host::"*.facebook.com" , Host::"*.instagram.com" ]
};
```

Permit database connections to an explicit host:port:

```cedar
permit (
    principal,
    action == Action::"NetworkConnect",
    resource
) when {
    resource in [ Host::"db.internal:5432" ]
};
```

## HTTP Rewrite Example

Leash can inject headers via the MITM proxy when `Action::"HttpRewrite"` is
used with contextual conditions:

```cedar
permit (
    principal,
    action == Action::"HttpRewrite",
    resource == Host::"api.example.com"
) when {
    context.header == "Authorization" &&
    context.value  == "Bearer prod-secret"
};
```

Each matching request to `api.example.com` receives the specified header and value before being forwarded upstream.

## MCP (Model Context Protocol) Examples

Leash monitors and enforces policies on MCP tool calls made by AI agents. MCP
policies use `Action::"McpCall"` with `MCP::Server` and `MCP::Tool` resources.

### V1 Enforcement Limitations

- **Deny-only enforcement**: `forbid` statements are enforced at runtime; `permit` statements are informational and generate linter warnings.
- **Server-level denies**: Denying an `MCP::Server` blocks all network connectivity to that host (transpiles to `net.send` deny).
- **Tool-specific denies**: Denying a specific `MCP::Tool` on an `MCP::Server` requires both resources; the proxy enforces tool-level access control.

### Block All Access to an MCP Server

Prevent any MCP communication with a specific server:

```cedar
forbid (
    principal,
    action == Action::"McpCall",
    resource
) when {
    resource in [ MCP::Server::"mcp.untrusted.com" ]
};
```

This transpiles to a network deny rule (`net.send mcp.untrusted.com`) and an MCP
policy rule blocking all tools on that server.

### Block a Specific Tool on a Server

Deny access to a specific MCP tool while allowing others:

```cedar
forbid (
    principal,
    action == Action::"McpCall",
    resource == MCP::Tool::"resolve-library-id"
) when {
    resource in [ MCP::Server::"mcp.context7.com" ]
};
```

The proxy will allow other tools on `mcp.context7.com` but deny calls to `resolve-library-id`.

### Informational Permit (V1)

In v1, `permit` on `McpCall` is recorded but not enforced:

```cedar
permit (
    principal,
    action == Action::"McpCall",
    resource == MCP::Tool::"safe-search"
) when {
    resource in [ MCP::Server::"mcp.internal" ]
};
```

This generates a linter warning (`mcp_allow_noop`) to indicate that allow rules are
not yet enforced. Use permit statements for documentation and future compatibility.

## Example Policy File

A small end-to-end policy might look like:

```cedar
// Allow basic file access while protecting secrets
permit (principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], resource)
when { resource in [ Dir::"/workspace/" ] };

forbid (principal, action == Action::"FileOpenReadWrite", resource)
when { resource in [ Dir::"/workspace/secrets/" ] };

// Allow execution of trusted tools
permit (principal, action == Action::"ProcessExec", resource)
when { resource in [ Dir::"/bin/", Dir::"/usr/bin/" ] };

forbid (principal, action == Action::"ProcessExec", resource)
when { resource in [ File::"/bin/rm" ] };

// Network policy
permit (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"api.internal" , Host::"db.internal:5432" ] };

forbid (principal, action == Action::"NetworkConnect", resource)
when { resource in [ Host::"*.facebook.com" ] };

// MCP tool access control
forbid (principal, action == Action::"McpCall", resource == MCP::Tool::"execute-shell")
when { resource in [ MCP::Server::"mcp.example.com" ] };

// Inject a header for internal API calls
permit (principal, action == Action::"HttpRewrite", resource == Host::"api.internal")
when {
    context.header == "X-Leash-Auth" &&
    context.value  == "service-token"
};
```

## Validation and Tooling

The daemon validates Cedar at startup and whenever policies change. Invalid policies
return structured errors with file, line, column, snippet, and a suggested fix. Lint policies using the REST API:

```bash
curl -fsS -X POST localhost:18080/api/policies/validate \
  -H 'Content-Type: application/json' \
  --data '{"cedar": "permit (principal, action == Action::\"FileOpen\", resource);"}'
```

Persistence is similarly performed through `/api/policies/persist` or via the
`leash` CLI (`leash policy apply ...`).

## Runtime Behavior Notes

- Cedar is the only persisted artifact. Generated IR never touches disk.
- Default posture is deny; `forbid` wins over a conflicting permit.
- Policies apply at the Leash container/cgroup scope; per‑principal enforcement not yet available.
- Directory resources must end with `/` to indicate recursive coverage.
- Hostname wildcards support leading `*.` only (e.g., `*.example.com`).
- IPv6 and CIDR resources are unsupported and will trigger lints.
