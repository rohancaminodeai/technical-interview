# SPEC — Single Point of Authentication (prototype contract)

This is the **single source of truth** for the prototype. Tests assert this spec; code satisfies
the tests. If behavior and this document disagree, the document wins (or the document is updated
first, deliberately). Design rationale lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
the [ADRs](docs/adr/).

---

## 1. Glossary

| Term | Meaning |
|---|---|
| **IdP / auth service** | Central service that authenticates users and issues tokens. The only place credentials are verified. |
| **Tenant service** | A workload app for one tenant. Validates tokens and resolves users locally. Never authenticates. |
| **Global identity** | One record per human in the IdP. Stable id = `sub`. |
| **Local user** | A row in a tenant's own DB, linked to a global identity via `idp_sub`. |
| **Entitlement** | A grant that a global identity may access a given tenant, with roles. |

---

## 2. Components & ports

| Component | Prototype port | Responsibility |
|---|---|---|
| `auth_service` | 8000 | `POST /login`, `GET /.well-known/jwks.json` |
| `tenant_service` (TENANT_ID=A) | 8001 | `GET /me`, `GET /data`, `GET /healthz` |
| `tenant_service` (TENANT_ID=B) | 8002 | same image, different `TENANT_ID` + DB |

Tenant ids in the prototype: `tenant_a`, `tenant_b`.

---

## 3. Token contract (JWT)

### 3.1 Header
```json
{ "alg": "RS256", "kid": "<key id>", "typ": "JWT" }
```
- `alg` is **always `RS256`**. Tenants MUST pin verification to `["RS256"]` and reject anything
  else (incl. `none`, `HS256`). See [ADR-0003](docs/adr/0003-rs256-asymmetric-signing.md).

### 3.2 Payload (claims)
```jsonc
{
  "iss": "https://auth.platform.local",   // issuer (constant for the prototype)
  "aud": "platform-tenants",              // audience (constant; shared by all tenants)
  "sub": "u_<uuid>",                      // stable GLOBAL user id
  "iat": 1700000000,                      // issued-at (epoch seconds)
  "exp": 1700000900,                      // expiry; TTL = 900s (15 min) in prototype
  "jti": "<uuid>",                        // unique token id (reserved for future revocation)
  "email": "user@example.com",            // convenience; NOT used for authz
  "entitlements": {                       // REQUIRED. {} = no tenant access
    "tenant_a": ["member"],
    "tenant_b": ["admin"]
  }
}
```

**Constants (prototype):** `iss = "https://auth.platform.local"`, `aud = "platform-tenants"`,
`TTL = 900` seconds, clock-skew leeway on verify = `60` seconds.

**Entitlement model:** `entitlements` is an object mapping `tenant_id → [roles]`. Presence of the
key grants tenant access; the role list is carried through to the tenant and surfaced on `/me`.
In the MVP the tenant gates only on **key presence** (tenant-level access); role-level
enforcement is out of scope but the data is plumbed through.

---

## 4. Auth service API

### 4.1 `POST /login`
Authenticate a user and issue a token.

**Request** (`application/json`):
```json
{ "email": "alice@example.com", "password": "s3cret" }
```

**Responses:**

| Status | When | Body |
|---|---|---|
| `200` | Credentials valid | `{ "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 900 }` |
| `401` | Unknown email **or** wrong password (indistinguishable) | `{ "detail": "invalid credentials" }` |
| `422` | Missing/empty `email` or `password` | FastAPI validation error |

**Rules:**
- Password verified with bcrypt against the IdP's stored hash.
- Unknown email and wrong password return the **same** `401` (no user enumeration) and MUST run a
  dummy hash comparison on unknown-email to avoid timing leaks.
- A valid user with **no entitlements** still gets `200` with `"entitlements": {}` (valid
  identity, no tenant access yet).
- The token's `entitlements` are read fresh from the IdP store at issue time.

### 4.2 `GET /.well-known/jwks.json`
Publish the public key so tenants can validate offline.

**Response `200`:**
```jsonc
{ "keys": [ { "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "<key id>", "n": "<b64url>", "e": "<b64url>" } ] }
```
- Always `200`, no auth required. Tenants fetch once and **cache**; this endpoint is not on the
  tenant request hot path.

---

## 5. Tenant service API

All data endpoints require `Authorization: Bearer <jwt>`. Validation order is normative — the
first failing check determines the status code.

### 5.1 Validation pipeline (normative order)

| Step | Check | Fail status |
|---|---|---|
| 1 | `Authorization` header present and well-formed (`Bearer <token>`) | `401` |
| 2 | Signature verifies against cached JWKS key, **alg pinned `["RS256"]`** | `401` |
| 3 | `exp` / `nbf` valid within ±60s skew | `401` |
| 4 | `iss` == expected issuer **and** `aud` == `platform-tenants` | `401` |
| 5 | `entitlements` contains **this** `TENANT_ID` | `403` |
| 6 | `sub` resolves to a local `users` row via `idp_sub` | `403` |
| — | all pass | `200` |

> **Isolation invariant (the most important rule):** a token whose `entitlements` does not name
> this tenant MUST receive `403` at step 5 — *before* any tenant data is queried.

`401` bodies: `{ "detail": "<reason>" }` (e.g. `missing token`, `invalid token`, `token expired`).
`403` bodies: `{ "detail": "not entitled" }` (step 5) or `{ "detail": "no local user" }` (step 6).

### 5.2 `GET /me`
Returns the locally-resolved identity for the token's `sub`.

**`200`:**
```json
{
  "tenant": "tenant_a",
  "idp_sub": "u_8f3a…",
  "local_user_id": 42,
  "email": "alice@example.com",
  "roles": ["member"]
}
```
`roles` echoes the entitlement roles for this tenant from the token.

### 5.3 `GET /data`
Returns a tenant-isolated resource proving the request is scoped to this tenant only.

**`200`:**
```json
{
  "tenant": "tenant_a",
  "owner": "alice@example.com",
  "items": [ { "id": 1, "label": "Tenant A record" } ]
}
```
- `items` come **only** from this tenant's DB. A token entitled to both tenants still gets each
  tenant's *own* rows from each tenant — never the other's.

### 5.4 `GET /healthz`
Liveness. `200 { "status": "ok", "tenant": "tenant_a" }`. No auth.

---

## 6. Data model

### 6.1 IdP store (`auth_service`)
```
identities(
  sub            TEXT PRIMARY KEY,      -- "u_<uuid>"
  email          TEXT UNIQUE NOT NULL,
  password_hash  TEXT NOT NULL          -- bcrypt
)
entitlements(
  sub        TEXT NOT NULL,             -- FK -> identities.sub
  tenant_id  TEXT NOT NULL,
  roles      TEXT NOT NULL,             -- JSON array, e.g. ["admin"]
  PRIMARY KEY (sub, tenant_id)
)
```

### 6.2 Tenant store (each `tenant_service`)
```
users(
  id        INTEGER PRIMARY KEY,
  idp_sub   TEXT UNIQUE,                -- link to global identity (NULL until migrated)
  email     TEXT NOT NULL,
  -- legacy column retained for migration realism:
  password_hash TEXT                    -- pre-migration local hash; unused once idp_sub set
)
data_items(
  id     INTEGER PRIMARY KEY,
  owner_email TEXT NOT NULL,
  label  TEXT NOT NULL
)
```

---

## 7. Migration contract (`migrate.py`)

`migrate.py --tenant <tenant_id> --tenant-db <path> --idp-db <path>`

Backfills one tenant's local users into the IdP and links them. Behavior:

1. For each local `users` row with a non-null `email`:
   - **Upsert global identity** in the IdP keyed by `email` (dedupe humans across tenants by
     email). Import the local `password_hash` as the IdP `password_hash` if the identity is new.
   - **Upsert entitlement** `(sub, tenant_id)` with default roles `["member"]`.
   - **Stamp** `users.idp_sub = sub` on the local row.
2. **Idempotent:** re-running produces no duplicate identities, entitlements, or relinks.
3. Rows that already have `idp_sub` set are skipped (already migrated).
4. Prints a summary: `{imported, linked, skipped}` counts. Exit code `0` on success.

Email matching is exact + case-insensitive for the prototype. (Production: only *verified*
emails merge; unverified are kept separate — noted, not implemented.
See [ADR-0005](docs/adr/0005-zero-downtime-migration.md).)

---

## 8. Error contract summary

| Status | Meaning |
|---|---|
| `200` | Success |
| `401` | Authentication failed: bad/expired/tampered token, wrong alg, `iss`/`aud` mismatch, missing header, or bad login credentials |
| `403` | Authenticated but **not authorized** for this tenant: no entitlement (step 5) or no local mapping (step 6) |
| `422` | Malformed request body (FastAPI validation) |

---

## 9. Out of scope (prototype)

OIDC redirect/cookie SSO, refresh tokens, `jti` revocation denylist, MFA, key rotation (single
static key), real KMS, real MySQL (SQLite stands in), role-level enforcement inside tenants, and
the production PHP rewrite. All are discussed in the architecture docs, not built here.
See [ADR-0006](docs/adr/0006-prototype-scope.md).
