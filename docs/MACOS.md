# Leash on macOS

Leash on macOS can run natively with a companion app that installs two system extensions:

- Endpoint Security (ES) extension for exec/file monitoring
- Network Extension (NE) filter for per‑directory network policy

This is a native alternative to the Linux container path and does not launch the local HTTP MITM proxy on macOS. Leash on macOS does not use `sandbox-exec`. Native `--darwin` mode is still highly experimental.

## Requirements

- macOS 14+ (Sonoma or newer)
- Administrator approval to activate system extensions

## Install & Activate

1. Move `Leash.app` to `/Applications` and open it.
2. In the app window, activate both extensions:
   - Endpoint Security -> “Activate”
   - Network Filter -> “Activate”
3. Approve the prompts in System Settings when macOS asks for permission.

## Verify Status

1. System Settings -> General -> Login Items & Extensions -> Extensions
   - Network Extensions -> “Leash (Leash Network Filter)”
   - Endpoint Security Extensions -> “Leash (LeashES)”
   - On macOS 15+, change the view to “By Category” to find them quickly.
2. System Settings -> Network -> VPN & Filters -> “Leash Network Filter” should show a green indicator and “Enabled”.

## Full Disk Access

The ES extension needs Full Disk Access to observe events:

System Settings -> Privacy & Security -> Full Disk Access -> enable for “LeashES”.

## Darwin-Specific Commands

### Start the Darwin Server

```bash
leash --darwin exec <your_command>
```

This automatically starts the WebSocket API server and web interface at [localhost:18080](http://localhost:18080), if they are not already running.

### Stop the Darwin Server

```bash
leash --darwin stop
```

Stops the running server.

## Remove / Uninstall

Deleting `Leash.app` should delete the system extensions, but you can also use the the app UI (each section has a “Remove” button). You can also remove from the terminal:

```bash
systemextensionsctl uninstall W5HSYBBJGA com.strongdm.leash.LeashES
systemextensionsctl uninstall W5HSYBBJGA com.strongdm.leash.LeashNetworkFilter
```

## Troubleshooting

### Stream Logs

```bash
log stream --style compact --level debug --predicate 'subsystem == "com.strongdm.leash"'
```

Examples:
- Only network filter logs: add `AND category == "network-filter"`
- Watch a specific leash PID: pipe to `grep "leash=<PID>"`

### Console.app

- Open Console.app -> Start
- Search for `com.strongdm.leash` and switch the filter to “Subsystem”

## Known Limitations

- No HTTP header injection or rewrite on macOS: the local MITM proxy is not launched; enforcement is via the Network Extension only.
- MCP logging is not emitted on macOS today.
- IP range (CIDR) matching is not implemented yet; hostnames and single IPs are supported.
- Default network behavior is fail‑open for flows missing PID metadata; enable “Enforce rules for untracked processes” in Settings to evaluate them.
- `leash --darwin exec …` expects the companion CLI at `/Applications/Leash.app/Contents/Resources/leashcli`; moving the app can break launches.
- Requires macOS 14+ for extension activation.
- Only supports connecting to the server at `localhost:18080`
