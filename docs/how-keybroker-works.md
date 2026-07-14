# How Keybroker lets AI use secrets without seeing them

> Canonical article: [adilzuberi.com/writing/how-keybroker-works](https://adilzuberi.com/writing/how-keybroker-works)

Keybroker turns broad host authority into narrow named actions for AI tools. The model asks for a capability. A local service checks the request, records the decision and performs only the registered code for that capability. Credentials stay in the host's credential store or SSH agent.

The public alpha proves the broker foundation. It exposes one harmless capability, `system.status`. It does **not** yet perform SSH or authenticated API actions. Per-harness identity, narrow credential adapters and result filtering must land before the first key-backed capability.

## The problem

Coding workflows often use several models and harnesses. A frontier model may plan and review. A cloud coding model may implement a bounded slice. A local model may handle sensitive files. Each harness can load plug-ins, run commands and write logs.

Giving every harness direct credentials creates authority sprawl:

- secrets enter prompts or transcripts;
- child processes inherit environment variables;
- a narrow task receives a broad shell;
- the same reusable token spreads across several runtimes;
- a client can use a credential against targets outside the task.

Local inference does not remove those risks. “Local” says where the model runs, not what its harness, extensions, logs or operating-system account can do.

Keybroker separates model choice from authority. Models can change. Credentials remain on the host behind one capability boundary.

## Design rules

1. **Capabilities are actions, not secrets.** `service.status` is a valid shape. `get_password` is not.
2. **The broker performs the action.** It does not unlock a path or hand an unrestricted shell to the model.
3. **The grant includes the target.** Permission for one host or API endpoint is not a wildcard.
4. **Unknown requests fail closed.** There is no shell fallback.
5. **Audit is part of execution.** If Keybroker cannot record a normal decision, it blocks the invocation.
6. **Each host owns its authority.** Credentials, grants, sockets and audit files do not copy between nodes.
7. **No public listener.** The alpha uses a local Unix socket only.
8. **A model cannot approve itself.** High-risk actions need an approval source outside the requesting model.

## Architecture

```text
AI model
   │ tool request
   ▼
AI harness
   ├── MCP stdio adapter ──┐
   └── CLI client ─────────┤
                           ▼
                    0600 Unix socket
                           │
                           ▼
                    Keybroker service
                    ├── capability registry
                    ├── caller + policy check
                    ├── audit writer
                    └── capability implementation
                           │
                           ▼
                    small JSON result
```

Keybroker is a Go module with no third-party module dependency. The business rules live in the root package. The command-line interface and Model Context Protocol adapter are separate clients of the same service.

### CLI

The command-line client supports:

```text
keybroker serve
keybroker wait
keybroker capabilities
keybroker check <capability>
keybroker invoke <capability>
```

It returns JSON and uses distinct exit codes:

| Exit | Meaning |
|---:|---|
| `0` | Success |
| `1` | Broker fault, such as audit or connection failure |
| `2` | Invalid command use |
| `3` | Policy denial |

### MCP adapter

The MCP adapter speaks JSON-RPC over standard input and output. It supports MCP initialisation, ping, tool listing and tool calls. The alpha advertises one tool, `keybroker_system_status`, and routes it through the broker socket.

The adapter does not run capabilities itself. It cannot bypass the core policy or audit path.

### Unix socket

The service binds a mode `0600` Unix socket. It opens no TCP listener. A remote model reaches Keybroker only through an approved harness running on the same trusted host.

The transport enforces several limits:

- the decoder reads at most 64 KiB from each request;
- connections receive ten-second deadlines;
- malformed and unknown operations return generic errors;
- caller identity supplied by a client is overwritten with `local-user`;
- a normal file at the socket path is never replaced;
- a second broker stops if the existing socket answers;
- a stale socket is removed only after a refused connection proves no broker is listening.

### Capability registry and policy

The alpha registry contains one read-only capability:

```json
{
  "name": "system.status",
  "description": "Report whether the local Keybroker core is available.",
  "risk": "read-only"
}
```

Policy requires a caller, rejects unknown capabilities and allows only the current local caller labels. The service owns the identity used at the socket boundary.

This identity model is coarse. It proves that a process can act as the service account. It does not yet distinguish one AI harness from another process running as that account. Credential-bearing capabilities remain blocked until per-harness identity and grants exist.

### Audit

The service appends one JSON object per decision to a mode `0600` JSONL file. An event holds the UTC time, local caller, capability, decision, reason and redacted input.

Secret-shaped audit input keys are replaced with `[REDACTED]`. The redactor recognises names containing password, secret, token, authorisation, credential, private key and API key markers, including nested maps and lists.

The audit event is written before an allowed result is produced. If the write fails, the result changes to `audit unavailable` and the invocation returns an error.

The file is append-mode, not tamper-proof. A hostile service account or root user can alter the host and its records.

## Request lifecycle

```text
1. Discover    list registered capabilities
2. Request     send capability name and non-secret input
3. Identify    overwrite caller identity at the service boundary
4. Decide      check caller and capability
5. Record      append allow or deny decision
6. Act         run registered code for the capability
7. Return      send a small JSON result
```

The two current paths are easy to test:

```text
$ keybroker invoke system.status
{"allowed":true,"capability":"system.status","reason":"allowed by local policy","output":{"broker":"keybroker","status":"ok"}}

$ keybroker invoke secrets.reveal
{"allowed":false,"capability":"secrets.reveal","reason":"unknown capability"}
$ echo $?
3
```

No `secrets.reveal` capability exists. Keybroker denies and audits the unknown name. It does not ask a model to improvise or fall through to a shell.

## Planned use case: SSH service status

The first serious use case is a read-only SSH status check. This capability is a design target, not shipped alpha behaviour.

An agent often receives a full SSH session merely to answer “is this service running?” A Keybroker capability can bind the request to one caller, host, service and command shape:

```json
{
  "capability": "ssh.service_status",
  "input": {
    "host": "production-web",
    "service": "example.service"
  }
}
```

The planned grant would define:

- an approved harness identity;
- one allow-listed SSH host alias;
- one allow-listed systemd service;
- a fixed `systemctl is-active` method;
- read-only risk;
- a short timeout;
- a four-state output schema;
- audit fields that contain no credential;
- a result filter that rejects unexpected command output.

The adapter would ask the host's SSH agent to authenticate. It would not read or return private-key bytes. The model would not receive an interactive shell. A successful result would be shaped like:

```json
{
  "allowed": true,
  "capability": "ssh.service_status",
  "output": {
    "host": "production-web",
    "service": "example.service",
    "state": "active"
  }
}
```

Changing the host, service or method would produce a policy denial. An audit failure would block the query. Oversized or unsafe target output would not enter model context.

The same contract can support authenticated APIs. The broker can use a host-held token for one fixed request and return a typed subset of the response. It must never offer a capability that returns the token.

## Deployment model

The same limited core currently runs on one macOS laptop and two Linux hosts.

```text
laptop                       lab server                    production server
┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│ user service    │          │ systemd service │          │ systemd service │
│ private socket  │          │ private socket  │          │ private socket  │
│ local audit     │          │ local audit     │          │ local audit     │
│ local authority │          │ local authority │          │ local authority │
└─────────────────┘          └─────────────────┘          └─────────────────┘
```

Each node is independent. The laptop does not become an online secret server. Production does not borrow a key from the laptop. The hosts share source code, not authority.

The Linux systemd unit runs under a non-root service account, removes Linux capabilities, limits address families to Unix sockets, protects home and system paths, uses private runtime and state directories, sets umask `077` and restarts on failure.

The unit also runs `keybroker wait` after start. That command calls the real broker with a five-second deadline. systemd does not finish startup until the socket answers.

## Failure behaviour

| Failure | Behaviour |
|---|---|
| Missing caller | Deny |
| Unknown capability | Deny and audit |
| Disallowed caller | Deny and audit |
| Audit unavailable | Block invocation and return broker fault |
| Malformed request | Return generic invalid-request error |
| Existing live broker | Refuse the second service |
| Normal file at socket path | Refuse to replace it |
| Stale socket | Remove only after refused connection |
| Readiness deadline | Fail service start |

Fail-closed means no action is the safe state. Machine-readable errors and exit codes still tell a harness why work stopped.

## Security boundary

Keybroker reduces credential exposure. It does not protect a compromised host.

It is designed to prevent:

- reusable secrets entering prompts or tool results;
- broad shells standing in for narrow tasks;
- clients choosing their own identity;
- unknown capabilities running by accident;
- normal actions running without an audit record;
- a local broker becoming a public network service.

It does not stop root from replacing the binary, reading process memory or altering policy. A hostile process running as the same service account can reach the current socket. The audit file is not tamper-evident. Keybroker does not replace operating-system security, disk encryption, patching, account isolation or a hardware security module.

## Shipped, next and out of scope

| Shipped now | Next security slices | Non-goals |
|---|---|---|
| Capability discovery and fail-closed policy | Per-harness identity and grants | Secret-reveal tools |
| CLI and MCP over a private socket | Capability schemas and target allow-lists | Generic authenticated shell |
| Audit-before-action | Adapter interface and result filtering | Public broker API |
| Audit-input redaction | Read-only SSH service status | Shared credentials between hosts |
| macOS and hardened Linux services | Read-only authenticated API request | Model self-approval |
| Stale-socket and readiness recovery | Human approval gate for writes | Protection from hostile root |

## Run the alpha

Keybroker requires Go 1.24 or later.

```bash
git clone https://github.com/adilzuberi/keybroker.git
cd keybroker
go test ./...
go vet ./...
go build -o ./bin/keybroker ./cmd/keybroker
go build -o ./bin/keybroker-mcp ./cmd/keybroker-mcp
```

Start a throwaway service:

```bash
export KEYBROKER_SOCKET=/tmp/keybroker-demo.sock
export KEYBROKER_AUDIT_LOG=/tmp/keybroker-demo-audit.jsonl
./bin/keybroker serve
```

In a second shell, set the same variables and run:

```bash
./bin/keybroker capabilities
./bin/keybroker check system.status
./bin/keybroker invoke system.status
./bin/keybroker invoke secrets.reveal
```

The last command should return exit code `3`.

## Source trail

- [Broker and policy](../broker.go)
- [Audit writer and redaction](../audit.go)
- [Unix-socket service](../unix.go)
- [CLI](../cmd/keybroker/main.go)
- [MCP adapter](../cmd/keybroker-mcp/main.go)
- [Linux service definition](../deploy/keybroker.service)
- [Security model](security-model.md)
- [Contributing](../CONTRIBUTING.md)
- [Security reports](../SECURITY.md)

## Source of truth

The canonical Git remote is Forgejo. Forgejo's native push mirror publishes each commit to GitHub. Do not push changes directly to GitHub.

The canonical prose version of this guide is [adilzuberi.com/writing/how-keybroker-works](https://adilzuberi.com/writing/how-keybroker-works). If the site and repository copies drift, the site version wins.

The principle behind both is short: keep the credential inside the trusted machine, give the model a small verb, and return only the answer.
