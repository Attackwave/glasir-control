# Single sign-on for the console

Control validates OIDC access tokens (`--oidc-issuer`, `--oidc-audience`,
`--oidc-jwks`) and the console can sign users in with Authorization Code and
PKCE (`--oidc-client-id`, `--oidc-authorization-endpoint`,
`--oidc-token-endpoint`). This page shows what a provider has to be told.

Whatever the provider, it must:

1. **Allow the redirect URIs** `https://<control>/review` and
   `https://<control>/admin`.
2. **Allow CORS on its token endpoint** for the console's origin. The page
   redeems the code itself, as a public client without a secret.
3. **Put Control's audience in the access token.** Control refuses a token
   without `aud`, `iss` or `exp`, and one whose audience or issuer differs.
4. **Name the user in a claim Control can use** (`--oidc-subject-claim`).
   Letters, digits, `_ - . @ +` are accepted, so `anna.schmidt` and
   `anna@example.com` work; whitespace, quotes and slashes do not.

Groups reach rights through `group <name> <role>` lines in `rights.tsv`, read
from the claim `--oidc-groups-claim` names (default `groups`).

The JWKS is a local file Control re-reads when it changes. Refresh it from the
provider's `jwks_uri` on a schedule shorter than the provider's key rotation,
for example with a sidecar or a cron job writing the file atomically.

## Keycloak

Tested in CI: `scripts/test-console-sso-keycloak.sh` signs in through
Keycloak 26.4's own login page with the realm in `scripts/keycloak-realm.json`.

- A client with **Client authentication off** (public), **Standard flow on**,
  **PKCE method S256**, the two redirect URIs, and **Web origins `+`** (the
  redirect URIs' origins).
- An **Audience** mapper on the client adding `glasir-control` (or whatever
  `--oidc-audience` says) to the access token. Without it Keycloak's tokens
  carry no usable audience and Control refuses them — the test checks that.
- A **Group Membership** mapper, claim `groups`, *Full group path* off.
- `--oidc-subject-claim preferred_username`, since `sub` is an opaque UUID.

```bash
glasir-control ... \
  --oidc-issuer https://sso.example.com/realms/engineering \
  --oidc-audience glasir-control \
  --oidc-jwks /run/glasir/jwks.json \
  --oidc-subject-claim preferred_username \
  --oidc-client-id glasir-console \
  --oidc-authorization-endpoint https://sso.example.com/realms/engineering/protocol/openid-connect/auth \
  --oidc-token-endpoint https://sso.example.com/realms/engineering/protocol/openid-connect/token
```

## Microsoft Entra ID

**Not yet tested against a tenant.** Written from Microsoft's documentation;
the points below are where Entra differs from the standard flow.

1. **Register an API for Control.** In *App registrations*, create
   "Glasir Control", open *Expose an API*, set the Application ID URI and add
   a scope, for example `access`. In its *Manifest*, set
   `"accessTokenAcceptedVersion": 2`, so tokens carry the v2 issuer and the
   API's **application (client) ID** as their audience.
2. **Register the console** as a second app, "Glasir Console". Under
   *Authentication*, add the two redirect URIs as platform
   **Single-page application**. Only that platform allows the token request
   from the browser; registered as *Web*, the token endpoint refuses it (CORS
   and `AADSTS9002326`). Under *API permissions*, add the delegated scope from
   step 1 and grant admin consent.
3. **Request the API's scope.** A token issued for Microsoft Graph cannot be
   validated by anyone but Graph, so the console must ask for Control's scope:
   `--oidc-scope "openid api://<control-app-id>/access"`.
4. **Choose the identity claim.** `preferred_username` is the user's UPN
   (`anna@example.com`); `oid` is a stable GUID. Rights name users by
   whichever claim is chosen.
5. **Prefer app roles over groups.** Entra puts group **object IDs** in
   `groups`, and replaces the claim with a reference once a user is in more
   than 200 groups ("groups overage"). App roles defined on the Control API
   arrive in `roles` and stay small: `--oidc-groups-claim roles`, and
   `group <role-value> <glasir-role>` in `rights.tsv`.

```bash
T=<tenant-id>
glasir-control ... \
  --oidc-issuer https://login.microsoftonline.com/$T/v2.0 \
  --oidc-audience <control-app-client-id> \
  --oidc-jwks /run/glasir/jwks.json \
  --oidc-subject-claim preferred_username \
  --oidc-groups-claim roles \
  --oidc-client-id <console-app-client-id> \
  --oidc-scope "openid api://<control-app-id>/access" \
  --oidc-authorization-endpoint https://login.microsoftonline.com/$T/oauth2/v2.0/authorize \
  --oidc-token-endpoint https://login.microsoftonline.com/$T/oauth2/v2.0/token
```

The JWKS is published at
`https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys`.
