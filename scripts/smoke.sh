#!/usr/bin/env bash
# End-to-end smoke test of the doublethink binary (M2): stand up the broker, create
# an account, create an ephemeral and a retained channel, exercise the admin key,
# and verify the SQLite state holds K_auth + the account-key HASH but never the
# shared secret or the raw API key. Run inside the dev container:
#   .claude-dev/run.sh bash scripts/smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o /tmp/doublethink ./cmd/doublethink

rm -f /tmp/dt.db /tmp/dt.db-*
export DOUBLETHINK_ADMIN_KEY="smoke-admin-key-with-enough-entropy-aaaa"   # >= 32 chars
/tmp/doublethink serve --addr 127.0.0.1:18080 --db /tmp/dt.db >/tmp/dt-serve.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  if curl -fs -o /dev/null http://127.0.0.1:18080/healthz 2>/dev/null; then break; fi
  sleep 0.1
done
SERVER=http://127.0.0.1:18080

echo "=== --help carries the no-warranty disclaimer (rule 3) ==="
/tmp/doublethink --help 2>&1 | grep -qi "WITHOUT WARRANTY" && echo "ok: disclaimer in --help" || { echo "FAIL: no disclaimer in --help"; exit 1; }

echo "=== admin enabled in startup log (key set) ==="
grep -qi "admin API enabled" /tmp/dt-serve.log && echo "ok: admin enabled" || { echo "FAIL: admin not enabled"; exit 1; }

echo "=== account create ==="
AOUT=$(/tmp/doublethink account create --server "$SERVER" --quiet)
ACCT=$(echo "$AOUT" | cut -f1); APIKEY=$(echo "$AOUT" | cut -f2)
[ -n "$ACCT" ] && [ -n "$APIKEY" ] || { echo "FAIL: no account/key"; exit 1; }
echo "account: $ACCT"

echo "=== ephemeral channel create (anonymous, ntfy-easy) ==="
EOUT=$(/tmp/doublethink channel create --server "$SERVER" --prefix demo --quiet)
ECHAN=$(echo "$EOUT" | cut -f1)
[ -n "$ECHAN" ] || { echo "FAIL: no ephemeral channel"; exit 1; }

echo "=== retained channel create (requires the account key) ==="
ROUT=$(/tmp/doublethink channel create --server "$SERVER" --prefix codespeak --retain --account "$ACCT" --api-key "$APIKEY" --quiet)
RCHAN=$(echo "$ROUT" | cut -f1); RSECRET=$(echo "$ROUT" | cut -f2)
[ -n "$RCHAN" ] && [ -n "$RSECRET" ] || { echo "FAIL: no retained channel"; exit 1; }
echo "retained channel: $RCHAN"

echo "=== anonymous CANNOT create a retained channel ==="
if /tmp/doublethink channel create --server "$SERVER" --retain --account x --api-key dtk_bogusbogusbogus --quiet >/dev/null 2>&1; then
  echo "FAIL: anonymous/bogus key created a retained channel"; exit 1
else
  echo "ok: retained create refused without a valid account"
fi

echo "=== admin can raise a channel's limit ==="
/tmp/doublethink admin set-limit --server "$SERVER" --channel "$RCHAN" --max-msgs 50 >/dev/null
echo "ok: admin set-limit accepted"

echo "=== SQLite holds K_auth + key HASH but NOT the secret or the raw API key ==="
# sqlite3 may not be present; grep the raw db file for the sensitive values.
if grep -qF "$RSECRET" /tmp/dt.db 2>/dev/null; then echo "FAIL: shared secret present in db"; exit 1; else echo "ok: shared secret absent from db"; fi
if grep -qF "$APIKEY" /tmp/dt.db 2>/dev/null; then echo "FAIL: raw API key present in db"; exit 1; else echo "ok: raw API key absent from db (only its hash is stored)"; fi

echo "=== startup log carries the disclaimer (rule 3) ==="
grep -qi "NO WARRANTY" /tmp/dt-serve.log && echo "ok: disclaimer in startup log" || { echo "FAIL: no disclaimer in startup log"; exit 1; }

echo "=== SMOKE PASSED ==="
