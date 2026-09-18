## Summary

Describe the problem and the intended change.

## Verification

- [ ] Tests or checks added or updated
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --locked -- -D warnings` passes
- [ ] `cargo test --locked` passes
- [ ] Production Kustomize overlay renders when deployment files changed

## Security and operations

- [ ] No credentials, private keys, or audit records are included
- [ ] Authorization, audit, and deployment impact is described
- [ ] Rollback is documented where the change affects production behavior
