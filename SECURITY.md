# Security

## Reporting a vulnerability

Open a [private security advisory](https://github.com/Attackwave/glasir-control/security/advisories/new)
on GitHub. Do not disclose exploitable weaknesses in a public issue or pull
request. A weakness in the Core it fronts belongs to
[Glasir](https://github.com/Attackwave/glasir/security/advisories/new).

Expect an acknowledgement within a week. There is no bounty programme.

## Supported versions

Fixes land on the latest release. Before 1.0 there are no backports: upgrade to
the newest `0.x` to receive a fix. Each release names its version, ships a
SHA-256 per archive and a CycloneDX SBOM, and the container image is signed
with Cosign and carries build provenance.

## Operational boundary

Glasir Control is the public policy and routing boundary; Glasir Core data
planes stay private. Deploy it with TLS, an OIDC issuer you operate, isolated
service credentials, and persistent protected audit storage. Review every
change to authorization policy through the configured approval process.

Never commit access tokens, OIDC client secrets, private keys, audit exports,
or production rights files. Use Kubernetes Secrets or an external secret
manager and rotate credentials independently.
