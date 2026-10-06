# Read-only node inspection contract

Status: owner-approved inspection completed on 6 October 2026. The exception
expired at the end of that inspection; it is not a standing SSH grant. Existing credentials and host pins stay in their current custody.
This exception permits inspection only; it does not enrol a Keybroker SSH action.

| Node | Routing clue from current canonical records | Expected account/home, to verify |
|---|---|---|
| ai1 | Existing ai1 SSH route | adilzuberi, /home/adilzuberi |
| ai2 | Existing ai2 SSH route | adilzuberi; same-UID /home/deploy is an additional runtime home |
| ai3 | Existing ai3 SSH route | adilzuberi, /home/adilzuberi |
| ai4 | Existing ai4 SSH route | adilzuberi, /home/adilzuberi |
| hai1 | Current personal edge route; hostname hai1 verified on 6 October; personal-edge-nbg1 is an older name | deploy, /home/deploy |
| umami-do-fra1 | Existing `ssh -F ~/.ssh/config-do-admin do-admin` route | Existing inspection account root; health runtime account unresolved |

Resolve saved SSH configuration metadata without reading key contents. Require
strict host-key checks, batch key-only authentication, no agent forwarding and a
bounded connection timeout. Stop on a hostname or host-key mismatch; do not accept
a new key or repair access within this inspection.

Collect only:

- Hostname, OS/architecture, UID, account names and the fixed runtime homes above.
- Existence, owner, mode and SHA-256 of selected Keybroker binaries in those homes
  and the fixed `/usr/local/bin/keybroker` and `/usr/local/bin/keybroker-mcp` paths.
- Fixed service metadata: active/enabled state, PID and runtime owner for
  `keybroker.service`, `keybroker-health.service` and any separately documented
  Firefly unit. Do not dump unit contents, environments, process arguments or logs.
- Availability/version of Python, systemd and sudo, plus ownership/mode of the
  proposed fixed installation parents. Do not invoke sudo or test administrator access.
- A health/discovery/denial canary only after its exact executable's provenance is
  established. Unknown executable hashes are reported for review rather than run.

No package installation, account change, file transfer, key modification, service
restart, provider request, secret-store access, enrolment or credential copy is
part of this contract. Never inspect barred folder names. Return safe metadata and
record a separate result for each node, including unreachable or uncertain states.

Source: [current six-node inventory](/Volumes/ai-vaults/Core/Context/documentation/aws-zuberi-ai-access-20261003.md)
and [network access record](/Volumes/ai-vaults/Core/Context/knowledge/references/access-hetzner-and-network.md).
