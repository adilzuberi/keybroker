# Security policy

Keybroker is security-sensitive alpha software. Its current public capability reports broker health. It does not yet provide credential-bearing actions.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting for `adilzuberi/keybroker` once the mirror is live.

Include the affected version, operating system, impact, reproduction steps and any proposed fix. Do not include real credentials, private keys or personal data.

## Supported versions

Only the latest commit on the default branch receives security fixes during alpha development.

## Security promises

- Unknown capabilities fail closed.
- An invocation does not run if its audit record cannot be written.
- The broker does not expose a TCP listener.
- Credentials must never be returned to a caller or written to an audit record.
- Security reports and fixes must include a regression test where practical.
