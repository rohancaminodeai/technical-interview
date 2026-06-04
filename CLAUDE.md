# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A prototype for **Single Point of Authentication**: log in once at a central IdP, reach every
tenant you're entitled to, without weakening per-tenant data isolation. Core principle —
**centralize authentication, keep authorization local**: the IdP proves *who you are* (RS256 JWT
with embedded `entitlements`); each tenant validates that token **offline** against the IdP's
public key (JWKS) and serves only its own data.

[SPEC.md](SPEC.md) is the **source of truth** — tests assert the spec, code satisfies the tests.
If behavior and SPEC.md disagree, the spec wins (or update the spec first, deliberately). Design
rationale lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/adr/](docs/adr/).

## Commands

```bash
make venv      # one-time: create .venv + install requirements
make test      # unit tests on the host — fast TDD loop, no containers/network
make up        # build + start the 3-service Docker stack (waits for health)
make e2e       # end-to-end tests against the running stack
make demo      # human-readable walkthrough (./demo.sh)
make down      # stop stack + remove volumes
make keys      # regenerate RSA keypair + JWKS (keys/gen_keys.py)
make seed      # rewrite demo DBs (seed.py)
```

Run a single unit test: `.venv/bin/python -m pytest tests/unit/test_jwt_tokens.py -q` (add
`-k <name>` to filter). `make e2e` **skips** with a clear message if the stack isn't up — run
`make up` first. Services: auth `:8000`, tenant_a `:8001`, tenant_b `:8002`.

## Architecture

Two FastAPI services plus shared code:

- **`auth_service/`** — the IdP, the *only* place credentials are verified. `POST /login` (bcrypt
  check → mint RS256 JWT) and `GET /.well-known/jwks.json`. Store: `identities` + `entitlements`.
- **`tenant_service/`** — one app, **run once per tenant** (same image, different `TENANT_ID` env
  + DB). `GET /me`, `/data`, `/healthz`. Never authenticates; validates tokens offline. Store:
  local `users` (linked to global identity via `idp_sub`) + `data_items`.
- **`common/`** — `config.py` (pinned constants, env-overridable) and `jwt_tokens.py`
  (`mint` runs only in auth; `verify` runs in every tenant and is the security-critical path).

**`create_app(...)` factories vs. `asgi.py`:** every service exposes a `create_app` factory that
takes its dependencies as arguments (db path, keys, JWKS, tenant id) so tests inject temp DBs and
ephemeral keys. The `asgi.py` entrypoint is the thin production wiring that reads keys from disk
and config from env. When adding behavior, add it to `app.py`'s factory, not the entrypoint.

**One image, many roles:** [Dockerfile](Dockerfile) builds a single image; [docker-compose.yml](docker-compose.yml)
decides what each container becomes via its `command` (auth vs. tenant) and `TENANT_ID`. A one-shot
`init` service generates keys + seeds DBs into shared bind-mounts; every other service waits on
`service_completed_successfully` so keys/DBs always exist first.

### The security contract (do not weaken)

The tenant validation pipeline order is **normative** (SPEC §5.1) — the *first* failing check
decides the status code:

```
1 header well-formed (Bearer <token>)      → 401
2 signature verifies, alg PINNED ["RS256"] → 401   (defeats alg:none / RS↔HS confusion)
3 exp/nbf within ±60s skew                 → 401
4 iss == issuer AND aud == platform-tenants → 401
5 entitlements contains THIS TENANT_ID     → 403   ← ISOLATION INVARIANT
6 sub resolves to local users row (idp_sub) → 403
```

Steps 1–4 are in `tenant_service/app.py::authenticate` (via `jwt_tokens.verify`); steps 5–6
follow. **Step 5 returns 403 before any tenant data is queried** — that is the isolation invariant
and the single most important test. Algorithm pinning lives in `jwt_tokens.verify`
(`algorithms=[ALGORITHM]`); never relax it. Login returns the **same** 401 for unknown email and
wrong password, and runs a dummy bcrypt compare on unknown-email to avoid timing/enumeration leaks.

### Offline validation & keys

Tenants validate tokens with a **cached JWKS public key** — no call to the auth service on the
request hot path (so the IdP being down doesn't block in-flight traffic; it only gates *new*
logins). `keys/private.pem` is git-ignored and must be generated (`make keys` or the `init`
service); unit tests don't need on-disk keys — `tests/unit/conftest.py` builds an ephemeral
keypair in-process using the real `keys/gen_keys.py` helpers.

## Migration

[migrate.py](migrate.py) backfills one tenant's legacy local `users` into the IdP, dedupes humans
by email into one global identity, grants the tenant entitlement, and stamps `idp_sub` back onto
the local row. It is **idempotent** (re-running skips already-linked rows) so a phased,
restartable, no-downtime rollout is safe (ADR-0005). Contract in SPEC §7.

## Scope

A prototype that makes the trust boundary explicit. SQLite stands in for MySQL. Out of scope
(discussed in docs, not built): OIDC redirect/cookie SSO, refresh tokens, `jti` revocation, MFA,
key rotation, real KMS, role-level enforcement inside tenants. See [ADR-0006](docs/adr/0006-prototype-scope.md).
