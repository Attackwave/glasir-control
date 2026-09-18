# Contributing to Glasir Control

Contributions are accepted through pull requests only; direct changes to
`main` are not part of the project workflow.

## Before opening a pull request

1. Create a focused branch from the current `main` branch.
2. Keep production code, comments, configuration, and user-facing
   documentation in English.
3. Add or update tests for every behavior or security-boundary change.
4. Run the required checks:

```sh
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
kubectl kustomize deploy/kubernetes/overlays/production
```

Do not commit generated output, credentials, editor state, or local assistant
configuration. Local workstation artifacts are excluded globally.

## Pull request expectations

Describe the problem, the intended behavior, the security impact, and the
evidence that verifies the change. Keep unrelated formatting and refactors out
of the same pull request. Authorization, audit, credential, and deployment
changes require an explicit rollback plan.

## Security-sensitive changes

Follow [SECURITY.md](SECURITY.md) for private reporting and coordinated fixes.

## License

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
