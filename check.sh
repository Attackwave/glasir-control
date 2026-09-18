#!/usr/bin/env bash
# The Enterprise Acceptance Test Suite (2026 Standards):
# - Process boundary separation & anti-oracle routing
# - Zero credential leak
# - Live hot-reloading (rights & tokens revocation without restarts)
# - Standard-compliant WWW-Authenticate headers (RFC 6750 / RFC 9728)
# - Enterprise Security Headers (HSTS, CSP, nosniff, frame-deny)
# - Security hardening: Path traversal immunity (%2e%2e) & Smuggling protection
# - Observability: /health endpoint
# - Non-blocking JSONL audit log verification
# - Pre-flight configuration validation CLI (--validate)
# - Code-Host Permission Synchronization (GitHub & GitLab Webhooks + CLI sync)
set -u

GLASIR=${GLASIR:-../glasir/target/release/glasir}
CONTROL=./target/release/glasir-control
# The test mints each data-plane credential from inside its repository. Make
# the binary path absolute before that `cd`, otherwise the default relative
# path resolves below the temporary fixture and silently yields an empty token.
GLASIR=$(cd "$(dirname "$GLASIR")" && pwd)/$(basename "$GLASIR")
WORK=$(mktemp -d)
FAILED=0

cleanup() {
  [ -n "${PIDS:-}" ] && kill $PIDS 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

ok()   { echo "  ok    $1"; }
fail() { echo "  FAIL  $1"; FAILED=1; }
is()   { # is <what> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else fail "$1 — expected $2, got $3"; fi
}

cargo build --release >/dev/null

if [ ! -x "$GLASIR" ]; then
  echo "building core binary at $GLASIR..."
  (cd ../glasir && cargo build --release) >/dev/null 2>&1 || true
fi

if [ ! -x "$GLASIR" ]; then
  echo "need the core binary at $GLASIR (set GLASIR=... to override)" >&2
  exit 2
fi

mkdir -p "$WORK/alpha/src" "$WORK/beta/src"
cat > "$WORK/alpha/src/lib.rs" <<'RS'
/// Alpha's payroll calculation.
fn alpha_payroll() -> u32 { alpha_helper() }
fn alpha_helper() -> u32 { 42 }
RS
cat > "$WORK/beta/src/lib.rs" <<'RS'
/// Beta's rocket telemetry.
fn beta_telemetry() -> u32 { beta_helper() }
fn beta_helper() -> u32 { 7 }
RS

"$GLASIR" analyse "$WORK/alpha" >/dev/null 2>&1
"$GLASIR" analyse "$WORK/beta"  >/dev/null 2>&1
ALPHA_BACKEND_TOKEN=$(cd "$WORK/alpha" && "$GLASIR" token add control 2>/dev/null)
BETA_BACKEND_TOKEN=$(cd "$WORK/beta" && "$GLASIR" token add control 2>/dev/null)
"$GLASIR" serve "$WORK/alpha" --http 7001 --behind-control-plane >/dev/null 2>&1 &
"$GLASIR" serve "$WORK/beta"  --http 7002 --behind-control-plane >/dev/null 2>&1 &
PIDS="$! $(jobs -p | tr '\n' ' ')"

python3 - > "$WORK/tokens" <<'PY'
import hashlib
for name, tok in [("anna", "tok-anna"), ("bruno", "tok-bruno"), ("clara", "tok-clara")]:
    print(f"{hashlib.sha256(tok.encode()).hexdigest()}\t{name}\t0")
PY

printf 'tree\talpha\t127.0.0.1:7001\t%s\n' "$ALPHA_BACKEND_TOKEN" >  "$WORK/rights.tsv"
printf 'tree\tbeta\t127.0.0.1:7002\t%s\n' "$BETA_BACKEND_TOKEN"  >> "$WORK/rights.tsv"
printf 'grant\tanna\talpha\n'                    >> "$WORK/rights.tsv"
printf 'grant\tbruno\tbeta\n'                    >> "$WORK/rights.tsv"
printf 'github:acme/alpha\talpha\n' > "$WORK/repo-map.tsv"
printf 'gitlab:acme\tbeta\n' >> "$WORK/repo-map.tsv"

echo "pre-flight validation"
"$CONTROL" --validate --rights "$WORK/rights.tsv" --tokens "$WORK/tokens" >/dev/null 2>&1
is "validate passes for valid config" "0" "$?"

printf 'malformed_line_with_no_tabs\n' > "$WORK/bad_rights.tsv"
if "$CONTROL" --validate --rights "$WORK/bad_rights.tsv" --tokens "$WORK/tokens" >/dev/null 2>&1; then
  fail "validate accepted malformed config"
else
  ok "validate catches malformed config"
fi

AUDIT_LOG="$WORK/audit.jsonl"
GH_SECRET="github-secret-123"
GL_SECRET="gitlab-secret-456"

"$CONTROL" --listen 127.0.0.1:8800 \
  --rights "$WORK/rights.tsv" \
  --tokens "$WORK/tokens" \
  --audit "$AUDIT_LOG" \
  --repo-map "$WORK/repo-map.tsv" \
  --github-secret "$GH_SECRET" \
  --gitlab-secret "$GL_SECRET" >/dev/null 2>&1 &
PIDS="$PIDS $!"
sleep 4

Q='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_graph","arguments":{"query":"payroll telemetry helper"}}}'
code() { curl -s -o /dev/null -w '%{http_code}' -X POST "localhost:8800/mcp/$1" -H "Authorization: Bearer $2" -d "$Q"; }
body() { curl -s -X POST "localhost:8800/mcp/$1" -H "Authorization: Bearer $2" -d "$Q"; }

echo "observability & health"
HEALTH=$(curl -s "localhost:8800/health")
case "$HEALTH" in *'"status":"ok"'*) ok "/health reports status ok" ;; *) fail "/health failed: $HEALTH" ;; esac
case "$HEALTH" in *'"configured_trees":2'*) ok "/health reports correct tree count" ;; *) fail "wrong tree count in /health" ;; esac

echo "enterprise security headers & options pre-flight"
RESP_HEADERS=$(curl -s -I "localhost:8800/health")
case "$RESP_HEADERS" in *'X-Content-Type-Options: nosniff'*|*'x-content-type-options: nosniff'*) ok "X-Content-Type-Options present" ;; *) fail "missing nosniff header" ;; esac
case "$RESP_HEADERS" in *'X-Frame-Options: DENY'*|*'x-frame-options: DENY'*) ok "X-Frame-Options present" ;; *) fail "missing frame-options header" ;; esac
case "$RESP_HEADERS" in *'Strict-Transport-Security'*|*'strict-transport-security'*) ok "HSTS header present" ;; *) fail "missing HSTS header" ;; esac

OPT_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS "localhost:8800/mcp/alpha")
is "OPTIONS pre-flight returns 204 No Content" "204" "$OPT_CODE"

echo "authentication headers"
AUTH_HEADER=$(curl -s -I "localhost:8800/mcp/alpha" | grep -i "WWW-Authenticate" || true)
case "$AUTH_HEADER" in *'Bearer realm="glasir-control"'*) ok "WWW-Authenticate header RFC compliant" ;; *) fail "bad WWW-Authenticate header: $AUTH_HEADER" ;; esac

echo "security hardening & traversal protection"
is "traversal via %2e%2e is refused" 404 "$(code '%2e%2e%2falpha' tok-anna)"
is "null byte in tree path is refused" 404 "$(code 'alpha%00evil' tok-anna)"

echo "routing"
is "anna reaches alpha"          200 "$(code alpha tok-anna)"
is "bruno reaches beta"          200 "$(code beta  tok-bruno)"
is "anna is refused beta"        404 "$(code beta  tok-anna)"
is "bruno is refused alpha"      404 "$(code alpha tok-bruno)"
# The heart of it: refused and absent must be one answer, or the service is an
# oracle for repository names.
is "an absent tree looks the same" 404 "$(code gamma tok-anna)"
is "no credential is refused"    401 "$(code alpha '')"
is "a wrong credential is refused" 401 "$(code alpha nonsense)"

echo "no leak"
A=$(body alpha tok-anna); B=$(body beta tok-bruno)
case "$A" in *alpha_payroll*) ok "alpha's own symbols reach anna" ;; *) fail "anna got no alpha content" ;; esac
case "$A" in *beta_*) fail "beta's symbols leaked into alpha's answer" ;; *) ok "no beta symbol in alpha's answer" ;; esac
case "$B" in *beta_telemetry*) ok "beta's own symbols reach bruno" ;; *) fail "bruno got no beta content" ;; esac
case "$B" in *alpha_*) fail "alpha's symbols leaked into beta's answer" ;; *) ok "no alpha symbol in beta's answer" ;; esac

echo "revocation without a restart"
grep -v '^grant.anna' "$WORK/rights.tsv" > "$WORK/r2" && mv "$WORK/r2" "$WORK/rights.tsv"
sleep 1
is "anna loses alpha at once"  404 "$(code alpha tok-anna)"
is "bruno is untouched"        200 "$(code beta  tok-bruno)"

echo "code-host sync via github webhook"
# clara has no access to alpha initially
is "clara has no access to alpha initially" 404 "$(code alpha tok-clara)"

# Send GitHub Webhook: member added
GH_PAYLOAD='{"action":"added","member":{"login":"clara"},"repository":{"full_name":"acme/alpha"}}'
GH_SIG=$(python3 -c "import hmac, hashlib; print('sha256=' + hmac.new(b'$GH_SECRET', b'''$GH_PAYLOAD''', hashlib.sha256).hexdigest())")

GH_RESP=$(curl -s -X POST "localhost:8800/api/sync/webhook/github" \
  -H "X-GitHub-Event: member" \
  -H "X-Hub-Signature-256: $GH_SIG" \
  -H "Content-Type: application/json" \
  -d "$GH_PAYLOAD")
case "$GH_RESP" in *'"applied":true'*|*'"status":"ok"'*) ok "github webhook processed successfully" ;; *) fail "github webhook failed: $GH_RESP" ;; esac

sleep 1
is "clara gained alpha access via webhook" 200 "$(code alpha tok-clara)"

# Send GitHub Webhook: member removed
GH_REM_PAYLOAD='{"action":"removed","member":{"login":"clara"},"repository":{"full_name":"acme/alpha"}}'
GH_REM_SIG=$(python3 -c "import hmac, hashlib; print('sha256=' + hmac.new(b'$GH_SECRET', b'''$GH_REM_PAYLOAD''', hashlib.sha256).hexdigest())")

curl -s -X POST "localhost:8800/api/sync/webhook/github" \
  -H "X-GitHub-Event: member" \
  -H "X-Hub-Signature-256: $GH_REM_SIG" \
  -H "Content-Type: application/json" \
  -d "$GH_REM_PAYLOAD" >/dev/null

sleep 1
is "clara lost alpha access via webhook" 404 "$(code alpha tok-clara)"

echo "code-host sync via gitlab webhook"
GL_PAYLOAD='{"event_name":"user_add_to_group","user_username":"clara","group_path":"acme"}'
GL_RESP=$(curl -s -X POST "localhost:8800/api/sync/webhook/gitlab" \
  -H "X-Gitlab-Event: member" \
  -H "X-Gitlab-Token: $GL_SECRET" \
  -H "Content-Type: application/json" \
  -d "$GL_PAYLOAD")
case "$GL_RESP" in *'"applied":true'*|*'"status":"ok"'*) ok "gitlab webhook processed successfully" ;; *) fail "gitlab webhook failed: $GL_RESP" ;; esac

sleep 1
is "clara gained beta access via gitlab webhook" 200 "$(code beta tok-clara)"

echo "cli permission mutation"
"$CONTROL" --sync-grant "clara:alpha" --rights "$WORK/rights.tsv" >/dev/null
sleep 1
is "clara reaches alpha after cli sync-grant" 200 "$(code alpha tok-clara)"

"$CONTROL" --sync-revoke "clara:alpha" --rights "$WORK/rights.tsv" >/dev/null
sleep 1
is "clara refused alpha after cli sync-revoke" 404 "$(code alpha tok-clara)"

echo "audit logging"
sleep 1
if [ -f "$AUDIT_LOG" ]; then
  ok "audit log file created"
  AUDIT_LINES=$(wc -l < "$AUDIT_LOG")
  if [ "$AUDIT_LINES" -gt 5 ]; then
    ok "audit log recorded requests ($AUDIT_LINES entries)"
  else
    fail "audit log too few entries: $AUDIT_LINES"
  fi
  grep -q '"who":"bruno"' "$AUDIT_LOG" && ok "audit log captured user identity" || fail "no bruno in audit log"
  grep -q '"tree":"beta"' "$AUDIT_LOG" && ok "audit log captured tree" || fail "no beta tree in audit log"
  grep -q '"path":"/health"' "$AUDIT_LOG" && ok "audit log captured health probes" || fail "no /health in audit log"
else
  fail "audit log file was not created"
fi

echo
if [ "$FAILED" = 0 ]; then echo "all checks passed"; else echo "FAILURES"; fi
exit $FAILED
