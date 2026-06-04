# Single Point of Authentication — prototype

Log in **once**, reach every tenant you're entitled to — **without** breaking
per-tenant data isolation. A central Identity Provider (IdP) verifies credentials
and issues a short-lived **RS256 JWT** carrying the user's tenant entitlements;
each tenant validates that token **offline** against the IdP's public key (JWKS)
and serves only its own data.

> **Core principle:** centralize *authentication*, keep *authorization* local.
> The IdP proves *who you are*; each tenant decides *what you can see* against its own DB.

- Design narrative + diagrams: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · visual reference: [docs/design.html](docs/design.html)
- Decisions: [docs/adr/](docs/adr/) (ADR-0001 … ADR-0006)
- The contract everything is tested against: [SPEC.md](SPEC.md)

## Architecture at a glance

```
                         ┌──────────────────────────┐
   POST /login           │   auth_service (IdP)      │   private key signs (RS256)
  ───────────────────▶   │   POST /login             │   public key via JWKS
                         │   GET  /.well-known/jwks  │
                         └────────────┬─────────────┘
            signed JWT {sub, entitlements, exp, …}   │ (tenants fetch + cache JWKS)
                         ┌────────────┴─────────────┐
   Authorization: Bearer │  tenant_service (×N)      │  verify offline → check
  ───────────────────▶   │  GET /me  GET /data       │  entitlement → resolve
                         │  own SQLite DB            │  sub→local user → serve
                         └──────────────────────────┘
```

Validation order at a tenant (first failure wins — SPEC §5.1):
`header → signature (alg pinned RS256) → exp/nbf → iss/aud → entitlement (403) → local user (403)`.
The entitlement check returns **403 before any data is queried** — that is the isolation invariant.

## Quick start

```bash
make venv      # one-time: create .venv + install deps
make test      # unit tests on the host (fast TDD loop)

make up        # build + start the 3-service Docker stack (waits for health)
make e2e       # end-to-end tests against the running stack
make demo      # human-readable walkthrough
make down      # stop + clean up
```

Services: **auth** → `:8000`, **tenant_a** → `:8001`, **tenant_b** → `:8002`.

### Demo UI

`make up` also starts a static web page at **http://localhost:8080**. Click the
*alice* / *bob* presets to log in, inspect the decoded token (with a live expiry
countdown), then call each tenant's `/me` and `/data` and watch the 200 vs **403**
isolation live. The *Sign up* tab registers a new identity in the IdP only — it
logs in fine but a tenant call returns **403 no local user**, showing that an
entitlement is not the same as being provisioned at the tenant. Click **Provision
here** on that tenant to close the gap (JIT provisioning — the tenant creates the
local user from the token), then `/me` and `/data` return **200**. (The browser
calls all three services directly; they allow the UI's origin via env-gated CORS.)

### Demo users (seeded)

| User | Password | Entitlements | Shows |
|---|---|---|---|
| `alice@example.com` | `alice-pw` | `tenant_a` | isolation: A → 200, B → **403** |
| `bob@example.com` | `bob-pw` | `tenant_a`, `tenant_b` | one login → both tenants 200 |

### Try it by hand

```bash
TOKEN=$(curl -s localhost:8000/login -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"alice-pw"}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl localhost:8001/data -H "Authorization: Bearer $TOKEN"   # 200 (entitled)
curl localhost:8002/data -H "Authorization: Bearer $TOKEN"   # 403 not entitled
```

## Migration (the ~50-tenant story)

`migrate.py` backfills one tenant's legacy local `users` into the IdP, dedupes
humans by email into a single global identity, grants the tenant entitlement, and
stamps `idp_sub` back onto the local row. It is **idempotent**, so a phased,
restartable rollout is safe:

```bash
python migrate.py --tenant tenant_a \
  --tenant-db data/tenant_a.sqlite --idp-db data/idp.sqlite
# migrated tenant_a: imported=N linked=N skipped=0   (re-run -> all skipped)
```

Full no-downtime / no-forced-re-auth strategy (dual-auth flag, dual-write, per-tenant
rollout, instant rollback): [ADR-0005](docs/adr/0005-zero-downtime-migration.md).

## Layout

```
auth_service/    central IdP: POST /login, JWKS  (store.py = identities + entitlements)
tenant_service/  one app, run per tenant: /me /data /healthz  (store.py = local users + data)
common/          config.py (pinned constants) + jwt_tokens.py (mint/verify, alg-pinned)
keys/            gen_keys.py — RSA-2048 keypair + JWKS (private key never committed)
migrate.py       legacy-tenant → IdP backfill (idempotent)
seed.py          deterministic demo data
tests/unit/      fast, no network (JWT, login, tenant pipeline, migration) — 38 tests
tests/e2e/       against the live Docker stack (SSO flow + isolation) — 9 tests
docs/            ARCHITECTURE.md, design.html, adr/
```

## Scope

A prototype that makes the trust boundary explicit. Out of scope (discussed in the
docs, not built): OIDC redirect/cookie SSO, refresh tokens, `jti` revocation, MFA,
key rotation, real KMS, real MySQL (SQLite stands in), the PHP rewrite. See
[ADR-0006](docs/adr/0006-prototype-scope.md).
