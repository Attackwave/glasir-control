#!/usr/bin/env bash
# The console's single sign-on in a real browser against a local provider:
# Authorization Code with PKCE, the token redeemed from the page, and a
# forged state refused. Needs node with `playwright` resolvable and Chromium.
set -euo pipefail

control_bin="$(realpath "${GLASIR_CONTROL_BIN:-target/release/glasir-control}")"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/glasir-sso.XXXXXX")"
idp_port="${SSO_IDP_PORT:-18990}"
control_port="${SSO_CONTROL_PORT:-18991}"
pids=""
trap 'kill $pids 2>/dev/null || true; rm -rf "$work"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/key.pem" 2>/dev/null
n=$(openssl rsa -in "$work/key.pem" -noout -modulus | cut -d= -f2 |
  python3 -c "import sys,base64; print(base64.urlsafe_b64encode(bytes.fromhex(sys.stdin.read().strip())).rstrip(b'=').decode())")
printf '{"keys":[{"kty":"RSA","kid":"k","n":"%s","e":"AQAB"}]}' "$n" > "$work/jwks.json"
printf 'tree\talpha\t127.0.0.1:1\tx\nrole\tadmin\talpha\nmember\tanna\tadmin\n' > "$work/rights.tsv"
: > "$work/tokens"

"$control_bin" --listen "127.0.0.1:$control_port" --rights "$work/rights.tsv" --tokens "$work/tokens" --no-audit \
  --oidc-issuer "http://localhost:$idp_port" --oidc-audience glasir-control --oidc-jwks "$work/jwks.json" \
  --oidc-client-id console \
  --oidc-authorization-endpoint "http://localhost:$idp_port/authorize" \
  --oidc-token-endpoint "http://localhost:$idp_port/token" >"$work/control.log" 2>&1 &
pids="$!"

idp() { # idp [forge-state]
  [ -n "${idp_pid:-}" ] && kill "$idp_pid" 2>/dev/null && wait "$idp_pid" 2>/dev/null || true
  python3 "$here/sso-idp.py" "$work/key.pem" "$idp_port" anna "$@" 2>>"$work/idp.log" &
  idp_pid=$!; pids="$pids $idp_pid"
  for _ in $(seq 50); do curl -s -o /dev/null "localhost:$idp_port/" && break; sleep 0.1; done
}

failed=0
echo "console single sign-on"
idp
node "$here/sso-browser.js" "http://localhost:$control_port" signed-in "${SSO_SCREENSHOT:-}" || failed=1
idp forge-state
node "$here/sso-browser.js" "http://localhost:$control_port" refused || failed=1
exit $failed
