# Demo

Glasir Core and Glasir Control in one container, with the two Glasir
repositories and five demo users. It shows the console (impact review, access
review, audit log, policy proposals with four-eyes approval, a tenant with its
own administrator) and the map of the Core repository.

One workspace, **platform**: Glasir and Glasir Control.

```sh
docker compose up --build
```

Open <http://localhost:8800/review> and sign in with one of these tokens:

| Token | User | Can |
|---|---|---|
| `demo-admin` | maria.keller | everything; has a pending policy proposal |
| `demo-admin-2` | jonas.weber | everything; approves maria's proposal (four eyes) |
| `demo-reviewer` | lena.fischer | impact review of both trees, three tools on glasir-control |
| `demo-developer` | tim.braun | glasir-core only |
| `demo-tenant-admin` | sara.klein | administers the tenant `control` (glasir-control): its access review, audit log and proposals only; has a pending proposal |

Approving replaces the whole policy, so once one of the two seeded proposals is
approved, the other is refused as made against an older policy. Its author
proposes again.

The map is on <http://localhost:7878>.

**Demo only.** The tokens are fixed and published here, and every start
rebuilds the clones, the credentials and the policy. Both ports bind to
localhost. For a real deployment see [`../README.md`](../README.md).

## Clone sources

`CORE_REPO` and `CONTROL_REPO` are clone sources. They can be URLs or paths inside
the container:

```sh
CORE_REPO=/src/core docker compose run --rm -p 127.0.0.1:8800:8800 \
  -v "$PWD/../../../glasir:/src/core:ro" demo
```

The tree names stay `glasir-core` and `glasir-control`, because the demo
policy names them.

## Versions

The image copies the binaries out of the published release images (Glasir
0.5.0 and Control 0.5.0 by default; the tenant needs at least Control 0.4.0). Choose other
releases with build arguments:

```sh
docker compose build --build-arg GLASIR_VERSION=v0.5.0 --build-arg CONTROL_VERSION=v0.5.0
```

Control listens on loopback only, as in production. Inside the container,
`socat` forwards port 8800 to it. That is why Core and Control share a
container here.
