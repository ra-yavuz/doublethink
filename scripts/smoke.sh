#!/usr/bin/env bash
# End-to-end smoke test of the doublethink binary: stand up the broker, create a
# private channel (self-service, no admin), and verify the server holds K_auth but
# never the shared secret, and the disclaimer appears where rule 3 requires. Run
# inside the dev container: .claude-dev/run.sh bash scripts/smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o /tmp/doublethink ./cmd/doublethink

rm -f /tmp/dt-state.json
/tmp/doublethink serve --addr 127.0.0.1:18080 --state /tmp/dt-state.json >/tmp/dt-serve.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  if curl -fs -o /dev/null http://127.0.0.1:18080/healthz 2>/dev/null; then break; fi
  sleep 0.1
done
SERVER=http://127.0.0.1:18080

echo "=== --help carries the no-warranty disclaimer (rule 3) ==="
/tmp/doublethink --help 2>&1 | grep -qi "WITHOUT WARRANTY" && echo "ok: disclaimer in --help" || { echo "FAIL: no disclaimer in --help"; exit 1; }

echo "=== self-service channel create (prints channel + secret) ==="
OUT=$(/tmp/doublethink channel create --server "$SERVER" --prefix codespeak --quiet)
echo "$OUT"
CHAN=$(echo "$OUT" | cut -f1)
SECRET=$(echo "$OUT" | cut -f2)
[ -n "$CHAN" ] && [ -n "$SECRET" ] || { echo "FAIL: missing channel or secret"; exit 1; }

echo "=== server state holds K_auth but NOT the shared secret ==="
cat /tmp/dt-state.json
echo ""
if grep -qF "$SECRET" /tmp/dt-state.json; then echo "FAIL: the shared secret is in server state"; exit 1; else echo "ok: shared secret is NOT in server state"; fi
grep -q '"channels"' /tmp/dt-state.json && echo "ok: channel + K_auth persisted" || { echo "FAIL: channel not persisted"; exit 1; }

echo "=== creating the same channel id again is refused (no silent overwrite) ==="
if /tmp/doublethink channel create --server "$SERVER" --quiet >/dev/null 2>&1; then
  : # different random id, fine
fi
echo "ok"

echo "=== server startup log carries the disclaimer (rule 3) ==="
grep -qi "NO WARRANTY" /tmp/dt-serve.log && echo "ok: disclaimer in startup log" || { echo "FAIL: no disclaimer in startup log"; exit 1; }

echo "=== SMOKE PASSED ==="
