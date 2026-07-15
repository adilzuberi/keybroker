# Keybroker request policy

Use this policy to decide what a model may request and what Keybroker may return.

## Data classes

| Class | Examples | Default route | Result rule |
|---|---|---|---|
| Public | Public sites, open-source code, published reports | Any approved model | Normal result |
| Internal | Private code, routine email, business documents | Local or approved cloud model | Read by default; approval for external writes |
| Restricted | Finance, tax, contracts, addresses, identity data | Local model first | Select fields, mask identifiers, time-bound access |
| Highly sensitive | Credentials, recovery codes, private keys, full health records, identity images | Credential never enters a model; data stays local by default | Temporary task-bound access and minimum necessary fields |

The user may raise a class. Do not lower one without an explicit policy change outside the requesting model.

## Action risks

| Risk | Examples | Gate |
|---|---|---|
| Observe | Status, list, search, selected record read | Policy check and audit |
| Prepare | Draft email, proposed change, staged transaction | Policy check; no external mutation |
| Change | Send, publish, edit, create, restart | Trusted approval unless explicitly pre-authorised by exact action and target |
| Destructive | Delete, revoke, rotate, transfer money, change permissions, account recovery | Exact human approval and narrow one-use grant |

## Capability contract

Define each credential-bearing capability with:

- a stable action name;
- an identified harness;
- one provider and account;
- allow-listed targets;
- fixed operation and input schema;
- data class and risk;
- timeout, row and output-size limits;
- result allowlist and redaction rules;
- approval rule;
- audit fields that contain no secret;
- a fail-closed response for unknown input or unavailable audit.

Never define `get_secret`, `unlock_path`, `authenticated_shell`, `fetch_any_url`, unrestricted SQL or a generic provider proxy.

## Model routing

1. Use deterministic local code when no model is needed.
2. Use a local model for restricted data and security-shaped interpretation.
3. Use an approved private cloud route only when the task needs a stronger model and the result can be minimised first.
4. Use a proprietary cloud model only with the smallest redacted context that completes the task.

Model strength does not expand authority. A frontier orchestrator may plan a task while a local worker handles the restricted records and returns a safe summary.

## Approval display

Build approval text from trusted structured fields, not from model prose or fetched content. Show the exact action, provider, account, target, scope, effect and expiry. For money movement, also show source, recipient, amount and reference.

## Safe response

Return a small typed result. Include enough technical detail for the task, but omit credentials, authentication headers, cookies, unrelated records, full identifiers and provider fields that were not requested. Let the model request another approved page or field set instead of returning everything at once.
