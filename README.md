# Keybroker

Keybroker is a local capability broker for approved AI tools. It grants named actions, not credentials. Each trusted host performs its own action and returns a redacted result.

## Current state

The alpha MVP is running and tested on macOS and Linux:

- One compiled Go core with no third-party dependencies.
- One harmless capability: `system.status`.
- Unknown capabilities fail closed.
- The caller label is checked against the local policy.
- Every invocation writes a private JSONL audit record.
- Secret-shaped input fields are replaced with `[REDACTED]` before audit.
- If the audit log cannot be written, the action does not run.
- CLI output is machine-readable JSON.
- A user LaunchAgent can keep one broker service running at login on macOS.
- The service listens on a user-owned `0600` Unix socket. It has no TCP listener.
- The service replaces caller-supplied identity with its own `local-user` identity.
- The CLI is a client of the service. It cannot bypass the broker core.
- A separate MCP stdio adapter exposes the same brokered capability to AI harnesses.
- The same core runs as an isolated, hardened systemd service on Linux.

The socket proves that a caller runs under the service account on its host. It does not yet tell one approved AI harness from another process running as that account. No Keychain, SSH, network or external-write capability exists yet.

For the full problem, architecture, request lifecycle, deployment model and planned read-only SSH use case, read [How Keybroker works](docs/how-keybroker-works.md). The canonical article is [adilzuberi.com/writing/how-keybroker-works](https://adilzuberi.com/writing/how-keybroker-works).

## Commands

Installed commands:

```bash
keybroker capabilities
keybroker check system.status
keybroker invoke system.status
keybroker wait
```

An unknown action returns a policy denial and exit code `3`:

```bash
keybroker invoke secrets.reveal
```

The default macOS audit path is:

```text
~/Library/Logs/Keybroker/audit.jsonl
```

Tests use a temporary audit path. Set `KEYBROKER_AUDIT_LOG` only when a test or harness needs a different non-secret location.

Linux defaults to `/run/keybroker/keybroker.sock` and `/var/lib/keybroker/audit.jsonl`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Request succeeded or policy check allowed it |
| `1` | Keybroker could not complete its own work, such as writing the audit record |
| `2` | Invalid CLI use |
| `3` | Policy denied the request |

## Architecture

The core owns capability discovery, policy checks, invocation and audit. A launchd or systemd service owns the live core. CLI and MCP are clients.

```text
CLI ─────┐
MCP ─────┴──> 0600 Unix socket ──> host service ──> Keybroker core
                                                  ├──> capability adapter ──> target
                                                  └──> redacted append-only audit
```

The next security slice adds per-harness grants above the Mac-user boundary. Only then does the first credential-bearing slice add one read-only SSH action through the existing SSH agent. It will not read private-key bytes.

## Build and test

Keybroker needs Go 1.24 or later and has no third-party dependencies.

```bash
go test ./...
go vet ./...
go build -o ./bin/keybroker ./cmd/keybroker
go build -o ./bin/keybroker-mcp ./cmd/keybroker-mcp
```

Start a development service with explicit private paths:

```bash
mkdir -p "$HOME/Library/Application Support/Keybroker" "$HOME/Library/Logs/Keybroker"
./bin/keybroker serve
```

In another shell:

```bash
./bin/keybroker capabilities
./bin/keybroker invoke system.status
```

## Deployment paths

| Purpose | Path |
|---|---|
| CLI | `~/.local/bin/keybroker` |
| MCP adapter | `~/.local/bin/keybroker-mcp` |
| LaunchAgent template | `deploy/com.keybroker.service.plist` |
| Unix socket | `~/Library/Application Support/Keybroker/keybroker.sock` |
| Audit log | `~/Library/Logs/Keybroker/audit.jsonl` |
| Service logs | `~/Library/Logs/Keybroker/service.log` and `service-error.log` |

Linux node paths:

| Purpose | Path |
|---|---|
| CLI | `/usr/local/bin/keybroker` |
| MCP adapter | `/usr/local/bin/keybroker-mcp` |
| systemd unit | `/etc/systemd/system/keybroker.service` |
| Unix socket | `/run/keybroker/keybroker.sock` |
| Audit log | `/var/lib/keybroker/audit.jsonl` |

## Security invariants

- No capability returns a password, token, private key or Keychain value.
- No generic authenticated shell.
- No public listener.
- No root process by default.
- No action without an audit record.
- No unknown action or caller.
- No access to protected `no-ai`, `private` or `secrets` paths.
- No credential or policy replication between hosts.

See [SECURITY.md](SECURITY.md) for vulnerability reports and [docs/security-model.md](docs/security-model.md) for the trust boundary.

## Open-source publishing

The public release uses one source path:

```text
local worktree → Forgejo adil/keybroker → automatic push mirror → GitHub adilzuberi/keybroker
```

Forgejo is canonical. GitHub is a read-only public mirror. Changes, tags and releases start in Forgejo; nobody pushes to GitHub by hand. The GitHub target must be empty before the first mirror sync.

The Forgejo repository is canonical. GitHub receives an automatic one-way push mirror and should be treated as read-only.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
