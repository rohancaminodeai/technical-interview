# ADR-0006: Prototype scope — Python/FastAPI, bearer-token slice, two Docker tenants

- **Status:** Accepted
- **Date:** 2026-06-03
- **Deciders:** Platform / Identity

## Context

This is a time-boxed exercise. A half-built prototype with clear design reasoning beats a
polished one with no architecture discussion. We must pick a stack and a scope that prove the
*trust model* — not production-harden it.

## Decision

**Stack:** Python 3 + FastAPI + PyJWT + SQLite. Fast to scaffold a clean three-service demo and
easy to read.

**Topology:** one central auth service + one parametrized tenant app run as **two Docker
containers** (`TENANT_ID=A`, `TENANT_ID=B`), each with its own SQLite DB.

**Flow:** minimal **bearer-token API slice** — `POST /login` returns a JWT; the client presents
it as `Authorization: Bearer` to each tenant. Same signature / entitlement / isolation semantics
as production OIDC, without browser redirects.

**Method:** SDD then TDD — write `SPEC.md` first, then drive each component test-first. Local
verification via `make test` (unit) and `make up` + `make e2e` / `make demo` (Docker).

**In scope (MVP):** `/login`, JWKS, tenant validation (RS256-pinned, `exp`/`iss`/`aud`,
entitlement check), `sub → idp_sub` local resolution, `migrate.py`, the cross-tenant 403
isolation test.

**Explicitly out of scope:** OIDC redirect/cookie SSO (narrated only), refresh tokens, `jti`
revocation denylist, MFA, real KMS, real MySQL (SQLite stands in), the PHP rewrite.

## Consequences

**Positive**
- Demonstrates the trust boundary, entitlement validation, and isolation invariant runnably and
  quickly.
- The narrated production design ([ARCHITECTURE.md](../ARCHITECTURE.md)) covers what the code
  intentionally omits.

**Negative / cost**
- Not production-ready: no redirect SSO, no revocation, SQLite not MySQL, single static key.
  These are deliberate, documented omissions — not gaps in the design.

## Related

[ARCHITECTURE.md](../ARCHITECTURE.md), all ADRs 0001–0005.
