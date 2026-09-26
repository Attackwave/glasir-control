#!/bin/sh
# Two real repositories behind Glasir Control, with demo identities.
# CORE_REPO and CONTROL_REPO are clone sources: a URL or a mounted path.
set -e
W=/work
# A restart starts over: the clones and credentials are rebuilt each time.
rm -rf "${W:?}"/* 2>/dev/null || true
git config --global --add safe.directory '*'
for t in "glasir-core $CORE_REPO" "glasir-control $CONTROL_REPO"; do
  name=${t%% *}; src=${t#* }
  # Enough history for the seeded impact review of HEAD~5.
  git clone -q --depth 50 "$src" "$W/$name"
  glasir analyse "$W/$name" >/dev/null 2>&1
done
CORE=$(cd $W/glasir-core && glasir token add control 2>/dev/null)
CTRL=$(cd $W/glasir-control && glasir token add control 2>/dev/null)
glasir serve $W/glasir-core --http 7101 --behind-control-plane >$W/core.log 2>&1 &
glasir serve $W/glasir-control --http 7102 --behind-control-plane >$W/ctrl.log 2>&1 &
: > $W/tokens
for pair in maria.keller:demo-admin jonas.weber:demo-admin-2 lena.fischer:demo-reviewer tim.braun:demo-developer; do
  printf '%s\t%s\t0\n' "$(printf %s "${pair#*:}" | sha256sum | cut -d' ' -f1)" "${pair%%:*}" >> $W/tokens
done
cat > $W/rights.tsv <<RIGHTS
tree	glasir-core	127.0.0.1:7101	$CORE
tree	glasir-control	127.0.0.1:7102	$CTRL
role	admin	glasir-core,glasir-control
role	platform-reviewer	glasir-core,glasir-control
role-tool	platform-reviewer	glasir-control	query_graph,impact,detect_changes
member	maria.keller	admin
member	jonas.weber	admin
member	lena.fischer	platform-reviewer
group	idp-platform-team	platform-reviewer
grant	tim.braun	glasir-core
workspace	platform	glasir-core,glasir-control
RIGHTS
glasir-control --validate --rights $W/rights.tsv --tokens $W/tokens
glasir-control --listen 127.0.0.1:8801 --rights $W/rights.tsv --tokens $W/tokens \
  --audit $W/audit.jsonl --policy-proposals $W/proposals \
  --allowed-origin "${PUBLIC_ORIGIN:-http://localhost:8800}" &
sleep 3
# Seed: a pending proposal by one administrator, and some traffic for the log.
{ cat $W/rights.tsv; printf 'grant\ttim.braun\tglasir-control\n'; } > $W/proposed.tsv
python_free_json() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g' -e 's/\t/\\t/g' "$1"; }
printf '{"id":"grant-tim-control","rights":"%s\\n"}' "$(python_free_json $W/proposed.tsv)" > $W/proposal.json
curl -s -o /dev/null -X POST -H 'Authorization: Bearer demo-admin' -H 'Content-Type: application/json' \
  --data @$W/proposal.json http://127.0.0.1:8801/api/admin/policy/proposals
curl -s -o /dev/null -X POST -H 'Authorization: Bearer demo-reviewer' -H 'Content-Type: application/json' \
  -d '{"workspace":"platform","rev":"HEAD~5","depth":3}' http://127.0.0.1:8801/api/review/impact
curl -s -o /dev/null -X POST http://127.0.0.1:8801/mcp/glasir-control -H 'Authorization: Bearer demo-developer' -d '{}'
curl -s -o /dev/null http://127.0.0.1:8801/workspaces -H 'Authorization: Bearer wrong-token'
glasir view $W/glasir-core --port 0.0.0.0:7878 >$W/view.log 2>&1 &
echo "Map of glasir-core on http://localhost:7878"
echo "Glasir Control demo ready on ${PUBLIC_ORIGIN:-http://localhost:8800}/review"
exec socat TCP-LISTEN:8800,fork,reuseaddr TCP:127.0.0.1:8801
