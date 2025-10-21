# Secrets Injection

Leash enables safe header injection so real secrets never enter the governed target container.

## Pattern

1) Keep fake/placeholder tokens in agent config (e.g., `FAKE-TOKEN`).
2) Configure the manager to inject the real value at the proxy boundary.
3) Requests continue to work; logs show the placeholder while the proxy uses the real secret.

## Example (Prototype Mapping)

`./tmp/cfg/rewrite.conf`:

```
api.anthropic.com:Authorization:Bearer sk-ant-...
```

Agent config (e.g., `./tmp/auth/credentials.json`) holds `FAKE-TOKEN`. The proxy injects the real header on outbound requests to `api.anthropic.com`.

## Audit

All injections are recorded with host, header name, and decision for forensics.
