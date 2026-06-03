# ADR-0002: Embed entitlements in a JWT; validate offline

- **Status:** Accepted
- **Date:** 2026-06-03
- **Deciders:** Platform / Identity

## Context

The tenant needs two facts on every request: (1) is this a genuine, unexpired credential from
our IdP, and (2) is this user entitled to *this* tenant. How the credential carries entitlements
and how the tenant checks them defines the coupling between tenants and the IdP.

Options for the credential format:
- **Opaque token + introspection** — tenant calls the IdP on every request to resolve the token
  and its entitlements. Always fresh, instant revocation — but every tenant request now depends
  on IdP availability and adds a network round-trip (latency + a hard coupling that fails
  closed).
- **Self-contained JWT with embedded entitlements** — tenant validates the signature locally
  with a cached public key; entitlements travel inside the signed token. No per-request IdP
  call.

## Decision

Use a **self-contained JWT** that embeds an `entitlements` claim (`{tenant_id: [roles]}`), and
have tenants **validate it offline** using the IdP's public key (fetched once from the JWKS
endpoint and cached). Standard claims: `iss`, `aud`, `sub`, `iat`, `exp`, `jti`.

Bound the cost of embedding stale data:
- **Short TTL** (~5–15 min) so entitlement changes propagate quickly on the next token refresh.
- **`jti`** is included so a revocation denylist can be added later (out of MVP scope) for
  instant kill without abandoning offline validation.

## Consequences

**Positive**
- Steady-state validation is **offline** → tenants keep serving even if the IdP is briefly down
  (the resilience property in [ADR-0004](0004-availability-fail-open-closed.md)).
- No per-request latency to the IdP; the IdP is not on the hot path.
- Stateless — scales horizontally without a shared session store.

**Negative / cost**
- **Staleness window:** a revoked entitlement remains usable until the token expires. Mitigated
  by short TTL; instant revocation needs the optional `jti` denylist.
- Tokens are bearer credentials — must be sent over TLS and kept short-lived (replay risk
  bounded by TTL).
- Token size grows with the number of entitlements (fine for a user-in-a-few-tenants shape).

## Related

[ADR-0003](0003-rs256-asymmetric-signing.md) (why the signature is asymmetric),
[ADR-0004](0004-availability-fail-open-closed.md).
