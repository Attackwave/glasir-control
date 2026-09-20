#!/usr/bin/env bash
# Exercises the production trust boundary end to end: a user authenticates to
# Control, Control applies its policy and replaces that credential with the
# tree-specific backend token, and Core accepts it only over mutual TLS.
set -euo pipefail

control_bin="${GLASIR_CONTROL_BIN:-target/release/glasir-control}"
core_bin="${GLASIR_CORE_BIN:-}"
test -x "$control_bin"
test -n "$core_bin" && test -x "$core_bin" || {
  echo "GLASIR_CORE_BIN must name an executable Glasir Core binary" >&2
  exit 2
}
control_bin="$(realpath "$control_bin")"
core_bin="$(realpath "$core_bin")"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/glasir-core-control.XXXXXX")"
core_port="${GLASIR_CORE_E2E_PORT:-18985}"
control_port="${GLASIR_CONTROL_E2E_PORT:-18986}"
core_pid=""
control_pid=""
cleanup() {
  test -z "$control_pid" || kill "$control_pid" 2>/dev/null || true
  test -z "$core_pid" || kill "$core_pid" 2>/dev/null || true
  test -z "$control_pid" || wait "$control_pid" 2>/dev/null || true
  test -z "$core_pid" || wait "$core_pid" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT
failure() {
  code=$?
  echo "Core-Control integration failed (exit $code)" >&2
  test ! -f core.log || { echo "--- core.log ---" >&2; cat core.log >&2; }
  test ! -f control.log || { echo "--- control.log ---" >&2; cat control.log >&2; }
  exit "$code"
}
trap failure ERR

cd "$workdir"
mkdir repo
printf 'pub fn answer() -> u8 { 42 }\n' > repo/lib.rs

# The Core certificate is valid for the literal loopback address because the
# routing file deliberately uses an IP address in this isolated test.
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
  -subj /CN=glasir-core-control-test-ca -days 1 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout core.key -out core.csr \
  -subj /CN=localhost >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > core.ext
openssl x509 -req -in core.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out core.crt -days 1 -extfile core.ext >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout control.key -out control.csr \
  -subj /CN=glasir-control >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > control.ext
openssl x509 -req -in control.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out control.crt -days 1 -extfile control.ext >/dev/null 2>&1

backend_token='core-only-backend-token'
user_token='operator-only-user-token'
printf '%s\tcontrol\t0\n' "$(printf %s "$backend_token" | sha256sum | cut -d' ' -f1)" > repo/.glasir-tokens
printf 'tree\talpha\t127.0.0.1:%s\t%s\ngrant\toperator\talpha\n' "$core_port" "$backend_token" > rights.tsv
printf '%s\toperator\t0\n' "$(printf %s "$user_token" | sha256sum | cut -d' ' -f1)" > users.tokens

"$core_bin" serve "$workdir/repo" --http "127.0.0.1:$core_port" \
  --behind-control-plane --control-plane-cidr 127.0.0.0/8 \
  --tls-cert "$workdir/core.crt" --tls-key "$workdir/core.key" \
  --control-plane-client-ca "$workdir/ca.crt" > core.log 2>&1 &
core_pid=$!

for _ in $(seq 1 30); do
  if curl -fsS --max-time 1 --cacert ca.crt --cert control.crt --key control.key \
    "https://127.0.0.1:$core_port/ready" >/dev/null; then break; fi
  sleep 0.2
done

# A valid client certificate is not enough: the user credential must never be
# accepted by Core in place of the isolated backend credential.
direct_status="$(curl -sS -o direct.out -w '%{http_code}' --max-time 3 \
  --cacert ca.crt --cert control.crt --key control.key \
  -H "Authorization: Bearer $user_token" -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  "https://127.0.0.1:$core_port/mcp")"
test "$direct_status" = 401

"$control_bin" --listen "127.0.0.1:$control_port" \
  --rights "$workdir/rights.tsv" --tokens "$workdir/users.tokens" \
  --audit "$workdir/audit.jsonl" --audit-key-file <(printf '0123456789abcdef0123456789abcdef') \
  --backend-tls-ca "$workdir/ca.crt" --backend-tls-cert "$workdir/control.crt" \
  --backend-tls-key "$workdir/control.key" > control.log 2>&1 &
control_pid=$!

for _ in $(seq 1 30); do
  if curl -fsS --max-time 1 "http://127.0.0.1:$control_port/health" >/dev/null; then break; fi
  sleep 0.2
done

status="$(curl -sS -o reply.json -w '%{http_code}' --max-time 5 \
  -H "Authorization: Bearer $user_token" -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  "http://127.0.0.1:$control_port/mcp/alpha")"
test "$status" = 200
grep -Fq 'tools' reply.json
test -s audit.jsonl
grep -Fq '"tree":"alpha"' audit.jsonl

echo "Core-Control mTLS forwarding verified"
