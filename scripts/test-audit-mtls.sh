#!/usr/bin/env bash
# Proves the transport contract of the central audit path, not just its
# individual helpers: mandatory client authentication, HMAC acceptance, and a
# Control Plane event durably exported through mTLS.
set -euo pipefail

binary="${GLASIR_CONTROL_BIN:-target/release/glasir-control}"
test -x "$binary"
binary="$(realpath "$binary")"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/glasir-audit-mtls.XXXXXX")"
ingest_port="${GLASIR_AUDIT_INGEST_PORT:-18983}"
control_port="${GLASIR_AUDIT_CONTROL_PORT:-18984}"
ingest_pid=""
control_pid=""
cleanup() {
  test -z "$control_pid" || kill "$control_pid" 2>/dev/null || true
  test -z "$ingest_pid" || kill "$ingest_pid" 2>/dev/null || true
  test -z "$control_pid" || wait "$control_pid" 2>/dev/null || true
  test -z "$ingest_pid" || wait "$ingest_pid" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

cd "$workdir"
printf '0123456789abcdef0123456789abcdef' > ingest.key
printf 'abcdef0123456789abcdef0123456789' > audit.key

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
  -subj /CN=glasir-test-ca -days 1 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj /CN=localhost >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 1 -extfile server.ext >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj /CN=glasir-control >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 1 -extfile client.ext >/dev/null 2>&1

printf 'tree\talpha\t127.0.0.1:7001\tbackend-token\n' > rights.tsv
printf '%s\toperator\n' "$(printf token | sha256sum | cut -d' ' -f1)" > tokens.tsv

"$binary" --audit-ingest "127.0.0.1:$ingest_port" \
  --audit-ingest-store "$workdir/events.jsonl" \
  --audit-ingest-key-file "$workdir/ingest.key" \
  --audit-ingest-tls-ca "$workdir/ca.crt" \
  --audit-ingest-tls-cert "$workdir/server.crt" \
  --audit-ingest-tls-key "$workdir/server.key" > ingest.log 2>&1 &
ingest_pid=$!
sleep 1

# A trusted CA alone is insufficient: mTLS must reject a connection that has
# no client identity before any HTTP endpoint is processed.
if curl -fsS --max-time 3 --cacert ca.crt \
  "https://localhost:$ingest_port/v1/events" >/dev/null 2>&1; then
  echo "audit ingest accepted a client without a certificate" >&2
  exit 1
fi

"$binary" --listen "127.0.0.1:$control_port" \
  --rights "$workdir/rights.tsv" --tokens "$workdir/tokens.tsv" \
  --audit "$workdir/local.jsonl" --audit-key-file "$workdir/audit.key" \
  --audit-remote-url "https://localhost:$ingest_port/v1/events" \
  --audit-remote-key-file "$workdir/ingest.key" \
  --audit-remote-tls-ca "$workdir/ca.crt" \
  --audit-remote-tls-cert "$workdir/client.crt" \
  --audit-remote-tls-key "$workdir/client.key" > control.log 2>&1 &
control_pid=$!

for _ in $(seq 1 20); do
  if curl -fsS --max-time 1 "http://127.0.0.1:$control_port/health" >/dev/null; then break; fi
  sleep 0.2
done
sleep 1
test -s events.jsonl
grep -Fq '"path":"/health"' events.jsonl
echo "mTLS audit export verified"
