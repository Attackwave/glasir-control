# Security

## Reporting a vulnerability

Open a [private security advisory](../../security/advisories/new) on GitHub.
Do not disclose exploitable weaknesses in a public issue or pull request.

Expect an acknowledgement within a week. There is no bounty programme.

## Operational boundary

Glasir Control is the public policy and routing boundary; Glasir Core data
planes stay private. Deploy it with TLS, an OIDC issuer you operate, isolated
service credentials, and persistent protected audit storage. Review every
change to authorization policy through the configured approval process.

Never commit access tokens, OIDC client secrets, private keys, audit exports,
or production rights files. Use Kubernetes Secrets or an external secret
manager and rotate credentials independently.
