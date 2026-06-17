#!/usr/bin/env bash
# End-to-end smoke test of the doublethink binary and its MITM-resistant pairing:
# stand up the server, create a channel (enrolling peer A), invite peer B, redeem
# the invite (peer B gets a SAS), confirm, and verify the server holds no private
# key material and the disclaimer appears where rule 3 requires. Run inside the dev
# container: .claude-dev/run.sh bash scripts/smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o /tmp/doublethink ./cmd/doublethink

rm -f /tmp/dt-state.json /tmp/peerA.json /tmp/peerB.json
/tmp/doublethink serve --addr 127.0.0.1:18080 --admin-addr 127.0.0.1:18081 --state /tmp/dt-state.json >/tmp/dt-serve.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  if curl -fs -o /dev/null http://127.0.0.1:18080/healthz 2>/dev/null; then break; fi
  sleep 0.1
done
ADMIN=http://127.0.0.1:18081

echo "=== --help carries the no-warranty disclaimer (rule 3) ==="
/tmp/doublethink --help 2>&1 | grep -qi "WITHOUT WARRANTY" && echo "ok: disclaimer in --help" || { echo "FAIL: no disclaimer in --help"; exit 1; }

echo "=== channel create (enrols peer A) ==="
CHAN=$(/tmp/doublethink channel create --admin "$ADMIN" --prefix codespeak --identity /tmp/peerA.json --role agent --quiet)
echo "channel: $CHAN"
[ -n "$CHAN" ] || { echo "FAIL: no channel id"; exit 1; }

echo "=== invite peer B (single-use code) ==="
INV=$(/tmp/doublethink invite --channel "$CHAN" --identity /tmp/peerA.json --admin "$ADMIN")
echo "$INV"
CODE=$(echo "$INV" | grep -oE '^  [A-Z2-7]{20,}$' | tr -d ' ' | head -1)
[ -n "$CODE" ] || { echo "FAIL: no pairing code parsed"; exit 1; }
echo "code: $CODE"

echo "=== pair peer B (redeems code, gets SAS; NOT yet admitted) ==="
PAIR=$(/tmp/doublethink pair --channel "$CHAN" --code "$CODE" --identity /tmp/peerB.json --role pwa --admin "$ADMIN")
echo "$PAIR"
SAS=$(echo "$PAIR" | grep -oE '[A-Z2-7]{4}-[A-Z2-7]{4}' | head -1)
[ -n "$SAS" ] || { echo "FAIL: no SAS parsed"; exit 1; }
echo "SAS: $SAS"

echo "=== single-use: redeeming the same code again must fail ==="
if /tmp/doublethink pair --channel "$CHAN" --code "$CODE" --identity /tmp/peerB2.json --role pwa --admin "$ADMIN" >/dev/null 2>&1; then
  echo "FAIL: pairing code was reusable"; exit 1
else
  echo "ok: pairing code is single-use"
fi

echo "=== confirm (admits peer B after SAS match) ==="
/tmp/doublethink confirm --sas "$SAS" --admin "$ADMIN"

echo "=== server state holds 2 authorized keys and NO private material ==="
cat /tmp/dt-state.json
echo ""
grep -qi "priv" /tmp/dt-state.json && { echo "FAIL: private material in server state"; exit 1; } || echo "ok: no private material in server state"
KEYS=$(grep -cE '"[A-Za-z0-9+/]{43}=?"' /tmp/dt-state.json || true)
[ "$KEYS" -ge 2 ] && echo "ok: 2 authorized keys present" || { echo "FAIL: expected 2 authorized keys, found $KEYS"; exit 1; }

echo "=== peer identity files hold private keys, locally only ==="
grep -qi "sign_priv" /tmp/peerA.json && grep -qi "sign_priv" /tmp/peerB.json && echo "ok: both peers hold their own private keys locally" || { echo "FAIL: peer identity missing private key"; exit 1; }

echo "=== server startup log carries the disclaimer (rule 3) ==="
grep -qi "NO WARRANTY" /tmp/dt-serve.log && echo "ok: disclaimer in startup log" || { echo "FAIL: no disclaimer in startup log"; exit 1; }

echo "=== SMOKE PASSED ==="
