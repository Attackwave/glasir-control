# Production deployment reference

This reference runs the control plane as an unprivileged, loopback-only
systemd service. Terminate public TLS in an existing ingress or reverse proxy;
only that proxy may reach `127.0.0.1:8800`.

1. Create a locked-down service account and directories:

```sh
useradd --system --home /var/lib/glasir-control --shell /usr/sbin/nologin glasir
install -d -o glasir -g glasir -m 0700 /var/lib/glasir-control /var/log/glasir-control
install -d -o root -g glasir -m 0750 /etc/glasir-control
```

2. Install `glasir-control.service`, the validated `rights.tsv`, and an
environment file with only the code-host API token names required by your
deployment. Keep token files in a secrets mount (`0600`, owned by `glasir`).

3. Validate before every rollout:

```sh
glasir-control --validate \
  --rights /etc/glasir-control/rights.tsv \
  --tokens /run/secrets/glasir-control.tokens
systemctl enable --now glasir-control
curl --fail http://127.0.0.1:8800/ready
```

`/health` is liveness, `/ready` is the load-balancer gate, and `/metrics`
contains only bounded-cardinality Prometheus series. Back up the rights policy
from its source repository and the append-only audit log independently. Do not
back up backend service credentials into the policy repository.

## Incident runbook

1. **Control unavailable:** stop rollout escalation, inspect `/ready` and
   non-secret container logs, then validate the immutable image and policy.
   Never bypass the proxy or make a Core public to restore service.
2. **Audit drops:** if `glasir_control_audit_dropped_total` rises, preserve the
   current audit volume, increase IO capacity or reduce request pressure, and
   record the gap as an audit incident.
3. **Verification failure:** treat the trail as tampered or incomplete; make
   an immutable copy, restrict access, run `--verify-audit` using copied key
   material, and investigate from the last verified record. Never repair the
   original log.
4. **Quarterly restore:** restore a policy revision and encrypted audit copy in
   an isolated namespace, verify the signed chain, prove `/ready` and one
   authorized MCP call, then record observed RTO/RPO.

## Central audit ingest

For multi-region DR, configure `--audit-remote-url` and
`--audit-remote-key-file` together. Glasir signs the canonical JSON event in
`X-Glasir-Audit-Signature: sha256=<hmac>` and exports after its local signed
append succeeds. The supplied Kubernetes base requires mutually authenticated
TLS directly at the ingest service, adds default-deny NetworkPolicies, and
keeps the HMAC as an independent event-integrity check. A cross-cluster or
multi-region endpoint must preserve these properties, deduplicate retries,
append atomically to encrypted immutable/WORM storage and acknowledge only
after durable persistence. Alert on
`glasir_control_audit_remote_failed_total`; a local audit chain remains the
forensic fallback, not a replacement for central retention.

## Kubernetes

[`kubernetes/base/control-plane.yaml`](kubernetes/base/control-plane.yaml) is a hardened
reference deployment with two replicas, a loopback-only control-plane container
behind a minimal proxy sidecar, restricted service account, non-root users,
read-only root filesystems, seccomp, dropped Linux capabilities, probes, PDB,
and a default-deny NetworkPolicy.

Before applying it, replace `CHANGE-ME` values through your secret manager and
pin the control-plane and NGINX image digests. It requires a pre-provisioned,
encrypted, lock-capable `glasir-audit` PVC; use ReadWriteMany only when the
storage honours advisory locks. Replicas serialize writes and derive each HMAC
predecessor while holding that lock, so they cannot fork the signed chain.
The base also deploys `glasir-audit-ingest`; it needs a separate encrypted,
immutable `glasir-audit-ingest` PVC, and its `ingest.key` must equal
`glasir-control-policy/audit.remote.key`. Provision both via one External
Secret. Its `glasir-audit-mtls/audit.crt` must be signed by the same CA as the
control client and carry the service DNS SAN documented in the manifest. For
multi-region DR, use the same direct mTLS contract or an external append-only
endpoint. The HTTPS egress rule exists solely for optional GitHub/GitLab
reconciliation; replace it with your CNI's FQDN allowlist when available.
Apply the base with
`kubectl apply -k deploy/kubernetes`; only use the production overlay after
image digests and secret-manager resources are set. Apply
`kubernetes/monitoring.yaml` only on clusters with the Prometheus Operator.

## Release verification

After a `control-v*` tag is published, deploy an immutable digest, never a
mutable tag. Verify the keyless Cosign signature and SLSA provenance before
admission:

```sh
bash scripts/verify-image.sh \
  ghcr.io/ORG/glasir-control@sha256:REPLACE \
  ORG/glasir-be
```
