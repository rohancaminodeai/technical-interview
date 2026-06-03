# ADR-0004: Fail open for in-flight validation, fail closed for new auth

- **Status:** Accepted
- **Date:** 2026-06-03
- **Deciders:** Platform / Identity

## Context

Centralizing authentication ([ADR-0001](0001-centralize-authentication-local-authorization.md))
creates a dependency: if the IdP is unavailable, what happens to tenant traffic? We must decide,
per scenario, whether the system *fails open* (keeps serving) or *fails closed* (denies). The
offline-validation choice in [ADR-0002](0002-jwt-embedded-entitlements-offline-validation.md)
makes a graceful answer possible.

A bad design would couple every tenant request to IdP availability (then an IdP outage takes
down all 50 tenants), or — worse — invent identity locally when the IdP is unreachable (a
silent security hole).

## Decision

Split the behavior along the authn/authz seam:

| Scenario | Behavior | Why |
|---|---|---|
| IdP down, request carries a **valid, unexpired** token | **Fail OPEN** — serve | Tenant verifies offline with the cached public key; the IdP is not on the hot path |
| Token **expired** or **new login** while IdP down | **Fail CLOSED** — deny | Identity may never be minted or extended without the IdP. Never invent identity |
| Tenant process **boots** while IdP unreachable | Serve from baked/cached public key | Availability of the public key must not depend on a live IdP at boot |
| `jti` revocation feed unavailable (future) | Configurable; default fail closed for revocation checks | Revocation is a safety control; prefer denying when unsure |

## Consequences

**Positive**
- An IdP outage degrades gracefully: existing sessions keep working for up to one token TTL;
  only *new* logins and refreshes are blocked.
- No path ever fabricates identity offline — the security posture is explicit and conservative.
- Blast radius of an IdP outage is bounded in *time* (token TTL) rather than taking down all
  tenants instantly.

**Negative / cost**
- During an IdP outage, users whose tokens expire cannot re-authenticate until it recovers.
  Mitigated by IdP HA and a TTL chosen to balance freshness vs. outage tolerance.
- The "fail open" window equals the token TTL — a revoked user could linger that long if instant
  revocation isn't deployed (tracked in [ADR-0002](0002-jwt-embedded-entitlements-offline-validation.md)).

## Related

[ADR-0002](0002-jwt-embedded-entitlements-offline-validation.md).
