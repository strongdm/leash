# Telemetry

Leash ships with minimal, privacy-preserving telemetry so we can understand whether the tool is being used at all.

## Events

We emit at most two Statsig events per run:

- **`leash.start`** records the host `os`, `arch`, the operating `mode` (`runner`, `leashd`, or `darwin`), the Leash version, whether a subcommand was provided, boolean flags noting if major CLI switches (`-p/--policy`, `--listen`, `--no-interactive`, `--open`) were present, a SHA-256 hash of the current workspace path (`workspace_id`), and a random per-run session identifier (`session_id`). No flag values or arguments are sent.
- **`leash.session`** fires on shutdown and includes a rounded session duration, aggregate counts of policy updates and policy update errors, and echoes the same `workspace_id`/`session_id` pair so the two events can be joined server-side.

## Privacy Guardrails

- No usernames, hostnames, project names, command strings, policy contents, file paths, or other identifiers are ever transmitted; only the hashed workspace identifier is reported.
- Telemetry never persists locally, and session identifiers are freshly generated for each run.
- Requests are sent to `https://events.statsigapi.net/v1/rgstr`. Although we do not include IP addresses in the payload, the destination inevitably observes the source IP at the transport layer.

## Disable Switch

Set `LEASH_DISABLE_TELEMETRY` to any non-empty value before launching Leash to skip all telemetry entirely.
