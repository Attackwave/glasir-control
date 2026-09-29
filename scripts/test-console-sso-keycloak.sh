#!/usr/bin/env bash
# The console's single sign-on against a real Keycloak: its login page, its
# token endpoint with CORS, its access token with the audience and groups a
# realm maps. The local mock (test-console-sso.sh) checks PKCE and state;
# this checks that a provider companies run accepts what the page sends.
# Needs docker, and node with `playwright` resolvable and Chromium.
set -euo pipefail

control_bin="$(realpath "${GLASIR_CONTROL_BIN:-target/release/glasir-control}")"
here="$(cd "$(dirname "$0")" && pwd)"
image="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007}" # 26.4.7
kc_port=18995
control_port=18996
work="$(mktemp -d "${TMPDIR:-/tmp}/glasir-kc.XXXXXX")"
name="glasir-kc-$$"
pids=""
trap 'kill $pids 2>/dev/null || true; docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

mkdir -p "$work/import"
cp "$here/keycloak-realm.json" "$work/import/glasir.json"
chmod -R a+rX "$work/import"
docker run -d --name "$name" -p "127.0.0.1:$kc_port:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$work/import:/opt/keycloak/data/import:ro" \
  "$image" start-dev --import-realm >/dev/null
issuer="http://localhost:$kc_port/realms/glasir"
for _ in $(seq 120); do
  curl -sf "$issuer/.well-known/openid-configuration" >/dev/null && break
  sleep 1
done
curl -sf "$issuer/protocol/openid-connect/certs" > "$work/jwks.json"

printf 'tree\talpha\t127.0.0.1:1\tx\nrole\tadmin\talpha\ngroup\tplatform-team\tadmin\n' > "$work/rights.tsv"
: > "$work/tokens"
"$control_bin" --listen "127.0.0.1:$control_port" --rights "$work/rights.tsv" --tokens "$work/tokens" --no-audit \
  --oidc-issuer "$issuer" --oidc-audience glasir-control --oidc-jwks "$work/jwks.json" \
  --oidc-subject-claim preferred_username \
  --oidc-client-id glasir-console \
  --oidc-authorization-endpoint "$issuer/protocol/openid-connect/auth" \
  --oidc-token-endpoint "$issuer/protocol/openid-connect/token" >"$work/control.log" 2>&1 &
pids="$!"
for _ in $(seq 50); do curl -s -o /dev/null "localhost:$control_port/health" && break; sleep 0.1; done

echo "console single sign-on against Keycloak"
node "$here/sso-keycloak-browser.js" "http://localhost:$control_port" anna.schmidt anna-pass "${SSO_SCREENSHOT:-}"
