# Glasir Control

**The enterprise control plane for [Glasir Core](https://github.com/Attackwave/glasir).**
Glasir Control provides one governed entry point for many private Core data
planes. It enforces identity, repository authorization, policy review, audit
evidence, and pull-request checks without giving the public edge direct access
to source-graph storage.

```
cd /srv/alpha && ALPHA_TOKEN="$(glasir token add control)"
cd /srv/beta  && BETA_TOKEN="$(glasir token add control)"
glasir serve /srv/alpha --http 7001 --behind-control-plane --watch
glasir serve /srv/beta  --http 7002 --behind-control-plane --watch
# Public TLS terminates at the reverse proxy; the control plane stays loopback.
glasir-control --listen 127.0.0.1:8800 --rights rights.tsv --tokens users.tokens --audit audit.jsonl --github-secret <secret>
```

A client reaches a tree at `/mcp/<name>` with its own credential. Everything
else about Glasir is unchanged — this service knows where a tree is and who may
see it, never what is in it.

To try it without setting anything up, [`deploy/demo`](deploy/demo) runs Core,
Control and the console with two real repositories: `docker compose up --build`.

## Install

Control is a service for operators. Run the signed container image, or a
binary from [Releases](https://github.com/Attackwave/glasir-control/releases):

| Platform | Archive |
|---|---|
| Linux x86_64 | `glasir-control-<version>-linux-x86_64.tar.gz` |
| Linux ARM64 | `glasir-control-<version>-linux-arm64.tar.gz` |
| macOS Apple Silicon | `glasir-control-<version>-macos-arm64.tar.gz` |
| macOS Intel | `glasir-control-<version>-macos-x86_64.tar.gz` |
| Windows x86_64 | `glasir-control-<version>-windows-x86_64.zip` |

Each archive has a `.sha256` beside it. The image is
`ghcr.io/attackwave/glasir-control` for `linux/amd64` and `linux/arm64`;
deploy it by digest after verifying its signature and provenance
([release verification](deploy/README.md#release-verification)). Every Core it
routes to runs `glasir`, from the
[Core releases](https://github.com/Attackwave/glasir/releases).

## Product boundary

| Capability | Core | Control |
|---|---|---|
| Index and query one source tree | Yes | Routes to the responsible Core |
| Public identity and repository authorization | No | Yes |
| Policy review and access certification | No | Yes |
| Cross-repository review workspace | No | Yes, for explicitly authorized trees |
| Central audit export and operational endpoints | Local only | Yes |

This division is deliberate. A Core process never receives an unauthorised
public request; Control authenticates, authorises, and forwards only the
isolated backend credential for the selected tree.

[Operations and data boundaries](docs/operations.md) describes retained state,
recovery expectations, and the deployment contract.

## Separation is a process boundary

A tree a caller may not reach is never spoken to. There is no code path on
which a mistake here returns the wrong tree's data, because that data lives in
another process that was never asked — a stronger promise than a check in front
of shared state, and the reason the core did not grow a tenant map instead.

**A tree you may not reach answers exactly as one that does not exist.** Both
are `404`. Telling them apart would make this service an oracle for repository
names.

## Configuration & Live Reloading

`rights.tsv`, tab-separated, re-read when it changes so a revocation takes
effect on the next request:

```tsv
tree    alpha   127.0.0.1:7001  secret-a
tree    beta    127.0.0.1:7002  secret-b
grant   anna    alpha
grant   bruno   alpha,beta
role    developer alpha,beta
member  clara    developer
```

Use `ALPHA_TOKEN` and `BETA_TOKEN` from the preceding one-time commands in
place of the placeholders. They are distinct service credentials, stored only
as hashes by each Core, and can be revoked with `glasir token revoke control`.
The Core's `--behind-control-plane` mode rejects a public bind and `--token`,
so a control-plane deployment cannot accidentally degrade to a public shared
secret.

### Roles (RBAC)

Direct `grant` entries remain useful for exceptions. For normal team access,
define a role once and assign users to it:

```tsv
role    developer  alpha,beta
role    auditor    alpha
member  clara      developer
member  dora       developer,auditor
```

Roles are additive: a user receives the union of direct grants and assigned
roles. There is intentionally no order-sensitive `deny` rule. An undefined
role is a pre-flight validation error and grants nothing, so a typo cannot
widen access. The file is reloaded live; removing a member or tree from a role
takes effect on the next request.

For least-privilege agent roles, restrict a role/tree pair to explicit MCP
tools. A direct user grant remains full access for backwards compatibility;
an explicit role allowlist is fail-closed for every other tool:

```tsv
role      analyst  alpha
role-tool analyst  alpha  query_graph,get_node,shortest_path
member    erin     analyst
```

OIDC groups are never trusted as roles directly. Map each IdP group explicitly
to local roles; groups without a `group` entry grant nothing. The claim name is
configurable for providers that do not use `groups`:

```tsv
group     engineering  developer
group     security     auditor
```

```bash
glasir-control --oidc-groups-claim groups ...
```

A versioned file rather than a database is deliberate: when the policy is kept
in version control, its review history records who changed a right and when.
That history complements, rather than replaces, the runtime audit trail. When
rights are mirrored from a code host, this is the file mirroring updates.

For periodic access certification, export the evaluated policy structure
without backend credentials or tokens:

```bash
glasir-control --rights rights.tsv --access-review > access-review.json
```

The deterministic `glasir.access-review.v1` document separates direct grants,
local role members, mapped IdP groups, trees and tool policies. IdP group
membership remains explicitly external rather than being misrepresented as a
local user snapshot. `tool_access.mode` is deliberately explicit: `all` is
full MCP access and `allowlist` contains the only permitted tools.

`users.tokens` is the core's own format (`<sha256>\t<name>\t<expiry>`), so an
operator learns one thing and a later sign-in flow replaces only who writes it.

### OIDC resource-server mode

For a public deployment, use OIDC instead of static tokens. The control plane
accepts only RS256 access tokens whose issuer and audience match its explicit
configuration; the JWKS is a locally mounted, atomically refreshed file and is
reloaded on key rotation. Static tokens are not accepted when OIDC is enabled.

```bash
glasir-control --listen 127.0.0.1:8800 \
  --oidc-issuer https://login.example.com/realms/engineering \
  --oidc-audience https://glasir.example.com/mcp \
  --oidc-jwks /run/secrets/glasir-jwks.json \
  --repo-map mappings.tsv
```

The reverse proxy owns the public HTTPS endpoint and serves the corresponding
OAuth Protected Resource Metadata; the control plane validates the resulting
audience-bound bearer token before routing any tree. The configured subject and
group values must be safe Glasir identifiers; malformed identity claims are
refused rather than being copied into authorization or audit data.

For code-host mirroring, set `--sync-interval`, `--sync-max-age` and the names
of environment variables containing the provider tokens. The control plane
fetches GitHub repository collaborators and GitLab effective group members,
then atomically replaces all mapped tree grants in one write. Once the lease
expires after a failed reconciliation, the proxy returns `503` for every tree
rather than serving rights that may have missed a revocation. Webhooks
accelerate propagation; they are not treated as the complete source of truth.

```bash
export GLASIR_GITHUB_TOKEN=github-fine-grained-read-token
export GLASIR_GITLAB_TOKEN=gitlab-group-read-token
glasir-control ... --repo-map mappings.tsv --sync-interval 300 --sync-max-age 900 \
  --github-token-env GLASIR_GITHUB_TOKEN --gitlab-token-env GLASIR_GITLAB_TOKEN
```

### Pre-flight Configuration Validation

Verify configuration syntax, duplicate entries, socket addresses, and dangling grants before deployment:

```bash
glasir-control --validate --rights rights.tsv --tokens users.tokens
```

## Code-host permission synchronization

Permissions are **mirrored from code hosts** (GitHub, GitLab), ensuring repository access policies remain authoritative:

* **Explicit mappings required:** pass `--repo-map mappings.tsv`; an unmapped, even correctly signed webhook is ignored. This prevents repositories with the same bare name from being confused. Lines are `github:owner/repo<TAB>tree` or `gitlab:group/path<TAB>tree`.
* **GitHub Webhooks (`POST /api/sync/webhook/github`)**: Validates `X-Hub-Signature-256` HMAC-SHA256 and maps the canonical `repository.full_name`.
* **GitLab Webhooks (`POST /api/sync/webhook/gitlab`)**: Validates `X-Gitlab-Token` and maps the canonical group path from group-member events.
* **Atomic Live Mutation**: Writes to temporary file and renames atomically, triggering immediate zero-downtime hot reloading.
* **CLI Permission Mutation**:
  ```bash
  glasir-control --sync-grant anna:alpha --rights rights.tsv
  glasir-control --sync-revoke anna:alpha --rights rights.tsv
  ```

## Enterprise Observability & Audit Logging

- **Non-blocking Request & Audit Log**: Every request, routing decision, response status, duration, and payload volume is queued to a bounded background writer (`--audit <file>`). If the filesystem stalls, entries are dropped and counted rather than blocking requests or leaking memory.
- **Log Rotation & Permissions**: Automatically rotates at 10 MB (keeps `.1`), created with POSIX `0600` permissions.
- **Tamper-evident audit chain**: Supply `--audit-key-file /run/secrets/glasir-audit.key` (at least 32 random bytes) to HMAC-sign every record and link it to its predecessor. Verify the current log plus its retained rotation with `glasir-control --verify-audit audit.jsonl --audit-key-file /run/secrets/glasir-audit.key`. Store the key separately from the log; an unsigned legacy log cannot be verified retroactively.
- **Health, Readiness and Metrics**: `GET /health` reports liveness; `GET /ready` fails closed if the identity source, configured trees, or a permission-mirror lease is unusable; `GET /metrics` exposes bounded-cardinality Prometheus gauges and counters. These endpoints are only reachable on the control plane's loopback listener or through the operator's proxy boundary.
- **Bearer-token mode**: responds with an RFC 6750 challenge. OAuth/OIDC resource-server mode is intentionally not claimed until an issuer and audience validation are configured.

## Review and administration

Control serves one browser console at `GET /review` and `GET /admin`. It keeps
the entered bearer token in the tab's memory only and calls the same API used
by automation:

- **Impact review** — what a change touches across every repository of a
  workspace: risk and its reasons, changed symbols, dependent code by distance.
- **Access review** (administrators) — roles, members, mapped IdP groups,
  direct grants and tool allowlists, filterable and exportable as JSON. Backend
  credentials never appear.
- **Audit log** (administrators) — the recent request timeline, filterable by
  identity, path and outcome.
- **Policy changes** (administrators) — proposals with a line diff against the
  active policy; the author cannot approve their own proposal.

With OIDC configured, the console can also sign users in through the identity
provider: Authorization Code with PKCE, as a public client without a secret.
Register a client for it, allow the redirect URIs `https://<control>/review`
and `https://<control>/admin`, and make sure its access tokens carry the
audience Control checks. Then add:

```bash
glasir-control ... --oidc-issuer ... --oidc-audience ... --oidc-jwks ... \
  --oidc-client-id glasir-console \
  --oidc-authorization-endpoint https://login.example.com/realms/engineering/protocol/openid-connect/auth \
  --oidc-token-endpoint https://login.example.com/realms/engineering/protocol/openid-connect/token
```

The page redeems the code at the token endpoint itself, so that endpoint's
origin is the only one added to the console's `connect-src`, and the identity
provider must allow the console's origin for CORS. The access token stays in
the tab's memory; only the PKCE verifier and state survive the redirect, in
`sessionStorage`, and are removed when the user returns. `--oidc-scope`
changes the requested scopes (default `openid`). Both endpoints must be
`https`, except on loopback.

Pass the URL the console is served under with `--allowed-origin` (for example
`--allowed-origin https://control.example.com`). The browser sends it with
every write, and Control refuses any origin it was not told about — deriving
it from `Host` would reopen DNS rebinding. The console says so when it is
missing. Everything it loads comes from the binary itself: no external font,
script or stylesheet, so it works air-gapped under the strict CSP.

For cross-repository work, `GET /workspaces` lists only workspaces for which
the caller can access every participating tree. `POST /api/review/impact`
produces a bounded diff-impact review for an authorised workspace, and
`GET /api/workspaces/<name>/evidence` returns its declared contract evidence.
These endpoints do not grant access to an individual repository merely because
its name appears in a workspace.

A workspace review also joins HTTP across its repositories. Each Core reports
the routes it serves and the requests it sends (`http_surface`, in Glasir
releases after 0.3.0); Control matches a request in one tree to a route in another by verb
and path segments, the most specific route winning, as within a tree. A
changed handler lists its callers from the other repositories
(`cross_repo_callers`), and the console shows them beside the in-repository
dependents. A Core without the tool contributes nothing, and the review still
answers.

The policy file remains the source of truth. Treat review-console proposals as
an approval workflow around a versioned policy change: review the resulting
rights change, retain the approval evidence, and use the normal deployment
process to promote it.

## Endpoints

* `POST /mcp/<tree>`: Forwards MCP JSON-RPC call to authorized tree backend.
* `GET  /trees`: Lists caller's visible trees (unauthorized trees are hidden).
* `GET  /health`: Health and status metrics for orchestrators.
* `GET  /ready`: Fail-closed readiness for load balancers and Kubernetes.
* `GET  /metrics`: Prometheus metrics without user, repository or token labels.
* `POST /api/sync/webhook/github`: GitHub collaborator event webhook listener.
* `POST /api/sync/webhook/gitlab`: GitLab membership event webhook listener.
* `GET  /api/sync/status`: Code-host sync configuration status.

## Transport boundary

`glasir-control` refuses all non-loopback binds. Put it behind a TLS-terminating
reverse proxy and allow only that proxy to reach `127.0.0.1:8800`. Browser
origins are denied unless the exact origin is passed with `--allowed-origin`;
native MCP clients do not send `Origin`.

## Core mTLS

The production Core hop must use mutual TLS, not a CIDR allow-list alone. Pass
all three control-plane options together:

```sh
glasir-control --rights rights.tsv --tokens users.tokens \
  --backend-tls-ca /run/tls/ca.crt \
  --backend-tls-cert /run/tls/control.crt \
  --backend-tls-key /run/tls/control.key
```

Every routed Core must use `--tls-cert`, `--tls-key` and
`--control-plane-client-ca` for the same private CA. Its server certificate
must contain the Core Service DNS name used in `rights.tsv`; the control-plane
certificate must be a client-auth certificate from that CA. The flags are
all-or-nothing and the control plane fails to start if the key material is
missing or malformed. Store the files in workload secrets or an external
secrets provider, rotate the client and server credentials independently, and
keep the public edge TLS separate from this private hop.

## Building & Testing

```bash
cargo build --release
cargo test --locked
bash scripts/test-audit-mtls.sh
bash scripts/test-core-control-mtls.sh
```

Release pipelines build platform archives, publish a multi-architecture image,
attach a CycloneDX SBOM, create provenance, and sign the published manifest
with keyless Cosign. Verify a release by immutable digest as described in
[the deployment reference](deploy/README.md#release-verification); never treat
a mutable tag as admission evidence.

## Licence

Apache-2.0, as the Core. See `LICENSE` and `NOTICE`. Each release archive
carries the copyright notices and licence texts of every linked dependency in
`THIRD-PARTY-LICENSES.txt`, generated by `cargo about` from the tagged
`Cargo.lock`; all of them are permissive, and `about.toml` fails the build on
any licence it does not list.
