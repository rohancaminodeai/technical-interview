#!/usr/bin/env bash
# Human-readable walkthrough of the Single Point of Authentication prototype.
# Requires the stack to be running: `make up` first.
#
# Tells the whole story: log in ONCE at the central auth service, then watch the
# same token be honored or refused by each tenant purely on its entitlements —
# the cross-tenant 403 is the data-isolation guarantee. Finishes with a live
# migration of a legacy tenant into the IdP (idempotent on re-run).
set -euo pipefail

AUTH=${AUTH_URL:-http://localhost:8000}
TA=${TENANT_A_URL:-http://localhost:8001}
TB=${TENANT_B_URL:-http://localhost:8002}
PY=${PY:-.venv/bin/python}

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
dim()  { printf '\033[2m%s\033[0m\n' "$1"; }

login() {
  curl -s "$AUTH/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" \
    | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'
}

hit() { # url path token
  local code; code=$(curl -s -o /tmp/_demo_body -w '%{http_code}' "$1$2" -H "Authorization: Bearer $3")
  printf '    %-26s HTTP %s   %s\n' "$1$2" "$code" "$(cat /tmp/_demo_body)"
}

echo
bold "1) Log in ONCE as alice (entitled to tenant_a only)"
ALICE=$(login alice@example.com alice-pw)
dim  "   got a signed JWT from the central auth service"

echo
bold "2) The SAME token at each tenant — entitlements decide, not a per-site login"
hit "$TA" /data "$ALICE"
hit "$TB" /data "$ALICE"
dim  "   tenant_a: 200 (entitled).  tenant_b: 403 'not entitled' = ISOLATION INVARIANT."

echo
bold "3) Log in ONCE as bob (entitled to BOTH tenants)"
BOB=$(login bob@example.com bob-pw)
hit "$TA" /data "$BOB"
hit "$TB" /data "$BOB"
dim  "   one credential reaches both tenants — and each returns ONLY its own rows."

echo
bold "4) Negative checks"
hit "$TA" /data "garbage.token.here"
dim  "   tampered/garbage token -> 401."
printf '    %-26s HTTP %s\n' "$TA/data (no header)" "$(curl -s -o /dev/null -w '%{http_code}' "$TA/data")"
dim  "   missing Authorization header -> 401."

echo
bold "5) Migration: backfill a legacy tenant's local users into the IdP"
TMP=$(mktemp -d)
"$PY" - "$TMP" <<'PY'
import sys, sqlite3
from tenant_service import store as t
from auth_service import store as i
tmp = sys.argv[1]
tdb, idb = f"{tmp}/legacy_tenant.sqlite", f"{tmp}/idp.sqlite"
c = t.connect(tdb); t.init_db(c)
for e in ("dave@example.com", "erin@example.com"):
    c.execute("INSERT INTO users (email, password_hash) VALUES (?, 'legacy-hash')", (e,))
c.commit(); c.close()
i.init_db(i.connect(idb))
print(f"  created legacy tenant DB with 2 local users (no idp_sub yet)")
PY
dim  "   running migrate.py (first time)…"
"$PY" migrate.py --tenant tenant_c --tenant-db "$TMP/legacy_tenant.sqlite" --idp-db "$TMP/idp.sqlite" | sed 's/^/    /'
dim  "   running migrate.py AGAIN (must be idempotent — all skipped)…"
"$PY" migrate.py --tenant tenant_c --tenant-db "$TMP/legacy_tenant.sqlite" --idp-db "$TMP/idp.sqlite" | sed 's/^/    /'
rm -rf "$TMP"

echo
bold "Done. One login, many tenants — with tenant data isolation preserved."
