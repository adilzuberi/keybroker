# Agent skill

Keybroker ships a vendor-neutral agent skill at [`skills/keybroker/SKILL.md`](skills/keybroker/SKILL.md). It teaches an AI harness to discover live capabilities, keep credentials outside model context, classify private data, request narrow actions and fail closed when the broker cannot grant them.

## Install

Copy the whole `skills/keybroker` folder into the skill directory used by the AI harness. Common locations include:

```text
~/.codex/skills/keybroker
~/.claude/skills/keybroker
<workspace>/.agents/skills/keybroker
<workspace>/.claude/skills/keybroker
```

Harnesses without automatic skill discovery can read `skills/keybroker/SKILL.md` before a protected task.

## Invoke

Use the explicit skill name when the harness supports it:

```text
Use $keybroker to review the failed GitHub workflow. Read only.
```

The skill does not grant access by itself. It uses only capabilities exposed by the installed Keybroker service. The current public alpha exposes `system.status`; credential-backed actions remain blocked until per-harness identity and narrow adapters ship.

The skill and policy reference are released under the repository's Apache-2.0 licence.
