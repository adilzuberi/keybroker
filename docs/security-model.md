# Security model

Keybroker turns broad host authority into narrow named capabilities. The caller asks for an action. The broker checks policy, records the decision and performs only the registered action.

## Current boundary

- The broker runs as an unprivileged host account.
- CLI and MCP clients use a mode `0600` Unix socket.
- The service replaces caller-supplied identity at the socket boundary.
- The only current capability is `system.status`.
- Unknown callers and capabilities fail closed.
- Audit failure blocks invocation.
- There is no TCP listener or remote API.

Unix socket access proves that a process can act as the service account. It does not yet prove which AI harness made the request. Credential-bearing capabilities remain blocked until Keybroker has per-harness identity and grants.

## Non-goals

- Returning passwords, tokens or private-key bytes.
- Offering a generic authenticated shell.
- Letting a model approve its own high-risk action.
- Sharing credentials or grants between hosts.
- Treating a local model as safe merely because inference runs on the same host.

## Future capability rule

A credential-bearing adapter must define its allowed target, input schema, method, risk class, approval rule, timeout, output limit and redaction rule. It performs the action itself and returns a narrow result. It never returns the credential.

High-risk changes need tests for denial, audit failure, output redaction and process restart before release.
