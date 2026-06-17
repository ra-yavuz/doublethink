#!/usr/bin/env bash
# End-to-end smoke test of the doublethink binary: stand up the server, create a
# private channel, pair two peers, and verify the server holds no private key
# material and the disclaimer appears where rule 3 requires. Run inside the dev
# container: .claude-dev/run.sh bash scripts/smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o /tmp/doublethink ./cmd/doublethink

rm -f /tmp/dt-state.json
/tmp/doublethink serve --addr 127.0.0.1:18080 --admin-addr 127.0.0.1:18081 --state /tmp/dt-state.json >/tmp/dt-serve.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

# Wait for the public health endpoint to answer.
for _ in $(seq 1 50); do
  if curl -fs -o /dev/null http://127.0.0.1:18080/healthz 2>/dev/null; then break; fi
  sleep 0.1
done

echo "=== --help carries the no-warranty disclaimer (rule 3) ==="
/tmp/doublethink --help 2>&1 | grep -qi "WITHOUT WARRANTY" && echo "ok: disclaimer in --help" || { echo "FAIL: no disclaimer in --help"; exit 1; }

echo "=== channel create ==="
CHAN=$(/tmp/doublethink channel create --admin http://127.0.0.1:18081 --prefix codespeak --quiet)
echo "channel: $CHAN"
[ -n "$CHAN" ] || { echo "FAIL: no channel id printed"; exit 1; }

echo "=== pair peer A and peer B ==="
/tmp/doublethink pair --channel "$CHAN" --identity /tmp/peerA.json --admin http://127.0.0.1:18081
/tmp/doublethink pair --channel "$CHAN" --identity /tmp/peerB.json --admin http://127.0.0.1:18081

echo "=== server state holds 2 authorized keys and NO private material ==="
cat /tmp/dt-state.json
echo ""
grep -qi "priv" /tmp/dt-state.json && { echo "FAIL: private material in server state"; exit 1; } || echo "ok: no private material in server state"

echo "=== peer identity files DO hold private keys, locally only ==="
grep -qi "sign_priv" /tmp/peerA.json && echo "ok: peer A holds its own private key locally" || { echo "FAIL: peer identity missing private key"; exit 1; }

echo "=== server startup log carries the disclaimer (rule 3) ==="
grep -qi "NO WARRANTY" /tmp/dt-serve.log && echo "ok: disclaimer in startup log" || { echo "FAIL: no disclaimer in startup log"; exit 1; }

echo "=== SMOKE PASSED ==="
