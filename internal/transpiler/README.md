# Cedar to Leash Transpiler

This package provides a transpiler that converts Cedar policies into Leash's IR (Intermediate Representation) policy configuration.

## Overview

The transpiler uses the [cedar-go](https://github.com/cedar-policy/cedar-go) AST to parse Cedar policies and converts them into Leash's native policy format, which consists of:

- **LSM Policies**: File operations (open, exec), network operations (connect)
- **HTTP Rewrite Rules**: Header injection rules for HTTP requests

## Supported Cedar Policy Mappings

### Actions

Cedar Actions (PascalCase) map to Leash IR operations:

| Cedar Action | IR Operation | Description |
|--------------|--------------|-------------|
| `Action::"FileOpen"` | `file.open` | Open file (any mode) |
| `Action::"FileOpenReadOnly"` | `file.open:ro` | Open file read-only |
| `Action::"FileOpenReadWrite"` | `file.open:rw` | Open file for writing |
| `Action::"ProcessExec"` | `proc.exec` | Execute binary |
| `Action::"NetworkConnect"` | `net.send` | Network connection |
| `Action::"HttpRewrite"` | `http.rewrite` | HTTP header injection |
| `Action::"McpCall"` | MCP policy rules | MCP tool call enforcement |

### Resources

Cedar resource entities are mapped to Leash resource types:

| Cedar Resource | Leash Format | Description |
|---------------|--------------|-------------|
| `File::"<path>"` | Exact file path | Single file |
| `Dir::"<path>"` | Directory path ending with `/` | Directory and subdirectories |
| `Host::"<hostname>"` | Hostname or IP | Network host |
| `Host::"<hostname>:<port>"` | Hostname with port | Network host and port |
| `MCP::Server::"<hostname>"` | MCP server host | MCP server endpoint |
| `MCP::Tool::"<tool-name>"` | MCP tool name | Specific MCP tool |

### Effects

| Cedar Effect | Leash Action |
|-------------|--------------|
| `permit` | `allow` |
| `forbid` | `deny` |

## Usage

### As a Library

```go
import (
    "github.com/strongdm/leash/internal/transpiler"
)

func main() {
    transpiler := transpiler.NewCedarToLeashTranspiler()
    
    policies, httpRules, err := transpiler.TranspileFromString(cedarPolicyContent)
    if err != nil {
        log.Fatal(err)
    }
    
    // Use policies...
}
```

### Command Line Tool

```bash
# Install
# From repo root:
go build -C cmd/cedar-transpile -o ../../bin/cedar-transpile .

# Transpile a Cedar policy file
./bin/cedar-transpile -input policy.cedar

# Save to file
./bin/cedar-transpile -input policy.cedar -output policy.leash
```

## Example

### Input Cedar Policy

```cedar
permit (
    principal == User::"claude",
    action in [Action::"FileOpen", Action::"FileOpenReadOnly"],
    resource
)
when {
    resource in [
        File::"/etc/passwd",
        Dir::"/tmp/"
    ]
};

permit (
    principal == User::"claude",
    action == Action::"NetworkConnect",
    resource
)
when {
    resource in [
        Host::"api.anthropic.com",
        Host::"*.example.com"
    ]
};
```

### Output Leash Policy

```
allow file.open /etc/passwd
allow file.open /tmp/
allow file.open:ro /etc/passwd
allow file.open:ro /tmp/
allow net.send api.anthropic.com
allow net.send *.example.com
```

## Limitations

- Context-based conditions (e.g., `context.hostname like "*.example.com"`) are partially supported
- IPv6 addresses are not yet supported
- Complex Cedar expressions may not be fully supported
- HTTP header rewrite rules are supported via `Action::"HttpRewrite"` with `context.header/value`
- **MCP policies (V1 limitations)**:
  - `permit` on `Action::"McpCall"` is informational only (generates linter warning `mcp_allow_noop`)
  - Only `forbid` on `Action::"McpCall"` is enforced at runtime
  - Tool-only denies (`MCP::Tool` without `MCP::Server`) do not generate network (`net.send`) rules
  - Server-level denies transpile to both MCP policy rules and network deny rules

## Testing

```bash
cd leash
go test ./transpiler/... -v
```

## Architecture

The transpiler consists of three main components:

1. **CedarParser**: Parses Cedar policies using cedar-go AST
2. **CedarToLeashTranspiler**: Converts parsed Cedar policies to Leash IR
3. **Resource Extractor**: Extracts resources from policy conditions

The transpiler walks the Cedar AST using reflection to extract:
- Principal, action, and resource constraints
- Condition expressions
- Policy effects and annotations
