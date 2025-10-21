# Security Model

Leash combines kernel‑level enforcement (eBPF LSM) with an application‑layer proxy to provide defense‑in‑depth for agent workloads.

## Trust Boundaries

- Agent container: governed workload, scoped by cgroup.
- Manager container: privileged, attaches BPF programs and runs the HTTP(S) proxy.
- Host: remains outside governance; enforcement triggers only for allowed cgroups.

## Deny‑By‑Default

Policies aim for deny‑by‑default with explicit, explainable allows. Start in Record/Shadow to reduce friction and then enforce.

## Enforcement Layers

- Kernel (eBPF LSM):
  - `file_open` decisions including read vs. write
  - `bprm_check_security` for `proc.exec`
  - `socket_connect` for outbound `net.send`
- Proxy (HTTP[S]):
  - Allow/Deny per host
  - Header injection at the boundary (secrets never enter the agent)

## Scoping

Enforcement activates for specific cgroups only, avoiding host/system interference.

## Observability

Structured events via ring buffers are forwarded to a WebSocket for UIs and automations. See `docs/PROTOCOL.md`.

