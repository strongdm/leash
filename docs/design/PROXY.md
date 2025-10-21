# HTTP(S) Proxy Behavior

Leash includes a transparent proxy to control and observe HTTP(S) traffic from governed containers.

## Capabilities

- Allow/Deny per host
- TODO: Header injection at the proxy boundary (e.g., `Authorization`)
- Optional host‑scoped behavior (e.g., only inject for specific domains)

## Notes

- The proxy runs alongside the manager in the agent’s network namespace.
- Secrets are injected at the boundary; real tokens do not need to live in the target container.
- Certificate pinning by target services may prevent interception/injection; configure policies accordingly.

## Example: Authorization Injection

Simplest proof‑of‑concept mapping (prototype) via `./tmp/cfg/rewrite.conf`:

```
api.anthropic.com:Authorization:Bearer sk-ant-...
```

With a fake token stored in the agent (e.g., `FAKE-TOKEN`), the proxy replaces the outbound header value transparently.

See also: docs/SECRETS-INJECTION.md
