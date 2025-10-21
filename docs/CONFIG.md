# Leash Configuration Volumes

Leash stores persistent configuration at `$XDG_CONFIG_HOME/leash/config.toml`, falling back to `~/.config/leash/config.toml` when no XDG override is present. The file controls whether host developer configuration directories (for example `~/.codex`) are mounted into the container automatically.

## Schema Overview

```toml
[volumes]
# Global scope, applied to every project unless a project override exists.
codex = true
claude = false
"~/devtools" = "/workspace/devtools:ro"

[projects."/absolute/path/to/project"]
# Project scope overrides the global scope for the matching working directory.
codex = true

[projects."/absolute/path/to/project".volumes]
"./.dev" = "/workspace/dev:rw"
# Disable an inherited custom volume for this project
"~/devtools" = false
```

- **Global scope** (`[volumes]`) applies to every workspace.
- **Project scope** (`[projects."/abs/path".volumes]`) overrides the global setting for that directory. Paths are normalized and de-symlinked before they are written.
- When no persisted value exists, Leash prompts interactively (when possible) or skips the mount.
- Project section keys accept `~` and environment variables (for example `[projects."~/src/app"]` or `[projects."${HOME}/src/app"]`); Leash resolves them when the file is loaded.
- Custom bind volumes use the host path as the key and the container target (optionally suffixed with `:mode`) as the value. Host paths accept `~` expansion, environment variables, and (for project entries) relative paths. Optional `mode` values mirror Docker (`rw`, `ro`, `z`, …). Set the same key to `false` inside a project to suppress an inherited global volume.

## Environment Variables

Leash can inject deterministic environment variables into the agent and leash containers. Define global values under `[leash.envvars]` and project overrides at `[projects."/abs/path".envvars]`. Project entries win over global values, and repeated keys via the CLI `--env` flag always take precedence. When you need to override the default images or container names globally, use the environment variables `LEASH_TARGET_IMAGE`, `TARGET_IMAGE`, `LEASH_IMAGE`, and `TARGET_CONTAINER`.

```toml
[leash.envvars]
# Applied to every session unless overridden.
OPENAI_API_KEY = "sk-example"
DOTENV_PATH = "/workspace/.env"

[projects."/Users/alice/src/app".envvars]
# Overrides for this workspace only.
DOTENV_PATH = "/workspace/app/.env"
BACKEND_URL = "http://localhost:4000"
```

Running Leash from `/Users/alice/src/app` generates the following effective set (highest priority last):

1. Auto-detected API keys from the host shell (per subcommand, if present).
2. Global config (`OPENAI_API_KEY=sk-example`).
3. Project config (`DOTENV_PATH=/workspace/app/.env`, `BACKEND_URL=...`).
4. CLI overrides (`leash --env DOTENV_PATH=/tmp/dev.env --env EXTRA_FLAG=1 -- codex shell`).

Only the last value for a given key is emitted, so the CLI example above would replace the project-scoped `DOTENV_PATH` while preserving `OPENAI_API_KEY` and `BACKEND_URL`.

## Supported Tools

Leash automatically manages mounts for the following subcommands:

- `codex`
- `claude`
- `gemini`
- `qwen`
- `opencode`

For each subcommand, Leash maps the host directory `~/.<cmd>` to the container path `/root/.<cmd>` using a read-write (`:rw`) bind mount.

## Prompt Workflow

1. On startup, Leash resolves the target host directory for the selected subcommand.
2. If a project decision exists, it takes precedence over global configuration and no prompt appears.
3. When no persisted decision exists and Leash detects an interactive TTY, it prompts:
   - `Mount ~/.codex into the container? [y/N]` – declining finishes without mounting.
   - When accepted, Leash asks for the scope: `1) system-wide`, `2) only for /path/to/project`, `3) just this once`.
4. Choices 1 and 2 are written to `config.toml` atomically; choice 3 grants an ephemeral mount for the current run only.
5. If persistence fails (for example, the config directory is read-only), Leash logs a warning and still enables the mount for the current session.

Non-interactive runs (for example `--no-interactive` or when standard input/output are not TTYs) skip prompting entirely and rely exclusively on persisted choices.

## Troubleshooting

- **Resetting a decision:** remove the corresponding entry from `config.toml` and rerun Leash to be prompted again.
- **Host directory deleted:** persisted `true` decisions are ignored when the source directory is missing; recreate the directory or disable the mount.
- **Inspecting decisions:** run `go run .scratch/config-roundtrip` from the repository root to print effective decisions and computed mounts for the current working directory.

## Example

A developer accepts mounting `~/.codex` only for `/Users/alice/src/app`. The resulting configuration is:

```toml
[volumes]
claude = false
"~/scratch" = "/workspace/.scratch:rw"

[projects."/Users/alice/src/app"]
codex = true

[projects."/Users/alice/src/app".volumes]
"${HOME}/scratch" = false
```

When Leash runs from `/Users/alice/src/app`, it mounts `~/.codex` to `/root/.codex:rw` automatically. Running from a different directory falls back to the global setting (in this example, no mount for `codex`).
