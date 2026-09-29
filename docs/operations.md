# Control operations and data boundaries

Glasir Control is the policy and routing boundary for multiple private Core
processes. It is not a source-graph store: each Core owns the graph and source
tree for one repository.

## State and retention

The rights policy, token material, local audit chain, and any remote audit
credentials are operationally sensitive. Store them outside source control,
restrict access to the service identity, rotate credentials independently, and
define retention and deletion periods with the organisation's security and
privacy owners.

The local audit writer is bounded. A storage failure can drop audit records to
preserve request availability. For enterprise retention, use the remote audit
ingest path with protected durable storage and alert on delivery failures. The
local signed chain is a forensic fallback, not a replacement for central
retention.

## Availability and recovery

Readiness is the traffic gate: it fails when configured identity, trees, or a
mirrored-rights lease is unusable. Do not bypass Control or expose a Core
publicly to restore service.

Back up policy from its version-controlled source and audit data from its
protected storage independently. Periodically restore both in an isolated
environment, validate the audit chain, verify readiness, and complete one
authorised MCP request. Record the observed recovery time and data-loss window.

## Deployment contract

Terminate public TLS at an approved edge, keep Control on its loopback or
private network boundary, and use mTLS for every Control-to-Core connection.
The Kubernetes reference and incident runbook are in
[deploy/README.md](../deploy/README.md).
