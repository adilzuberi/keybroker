# Contributing

Keybroker is in early alpha. Small, test-backed changes are welcome.

## Development

```bash
go test ./...
go vet ./...
```

Keep the standard library as the default. Explain any new dependency and its security cost.

## Pull requests

- Keep each pull request to one security or product slice.
- Add tests before changing security-sensitive behaviour.
- Do not add generic shell, secret-reveal or unrestricted network capabilities.
- Do not commit credentials, private infrastructure names, personal paths or audit logs.
- Describe the trust-boundary change and the failure mode.

By contributing, you agree that your contribution is licensed under Apache-2.0.
