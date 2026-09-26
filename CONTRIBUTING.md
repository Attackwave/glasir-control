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
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
bash check.sh        # needs a Glasir Core binary: ../glasir built, or GLASIR=<path>
bash scripts/test-audit-mtls.sh
GLASIR_CORE_BIN=<core binary> bash scripts/test-core-control-mtls.sh
NODE_PATH=<dir with playwright> bash scripts/test-console-sso.sh
kubectl kustomize deploy/kubernetes/overlays/production   # when deployment files changed
```

CI runs the same, with the Core built from its `main` branch. A change that
needs a new Core feature therefore lands after the Core change.

Do not commit generated output, credentials, editor state, audit records or
assistant configuration.

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
