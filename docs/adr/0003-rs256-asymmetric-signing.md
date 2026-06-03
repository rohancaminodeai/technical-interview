# ADR-0003: Sign tokens with RS256 (asymmetric), not HS256

- **Status:** Accepted
- **Date:** 2026-06-03
- **Deciders:** Platform / Identity

## Context

The JWT from [ADR-0002](0002-jwt-embedded-entitlements-offline-validation.md) must be verifiable
by every tenant. The choice of signing algorithm decides what secret each tenant must hold.

- **HS256 (symmetric):** signer and verifier share the *same* secret. Every tenant would need
  the signing key — so any single compromised tenant could **forge tokens for all other
  tenants**. This directly violates the "tenants never trust each other" boundary
  ([ADR-0001](0001-centralize-authentication-local-authorization.md)).
- **RS256 (asymmetric):** the IdP signs with a **private** key; tenants verify with the
  **public** key. Tenants can verify but never sign.

## Decision

Sign with **RS256**. The private key lives only in the IdP (KMS in production); tenants fetch
the **public** key from the JWKS endpoint and cache it.

**Critical hardening:** tenants MUST pin verification to `algorithms=["RS256"]`.
- Reject `alg: none` (unsigned token forgery).
- Reject an attacker submitting an **HS256** token signed using the *public* key as the HMAC
  secret (the classic algorithm-confusion attack). If the verifier accepts HS256 while holding
  the public key as a "secret", forgery is trivial.

This is the single highest-priority security test in the suite.

## Consequences

**Positive**
- A compromised tenant cannot forge tokens — it only ever holds a public key.
- Public keys are safe to distribute and cache widely (enables offline validation).
- Supports key rotation via `kid` + JWKS without redistributing secrets.

**Negative / cost**
- Slightly heavier signing/verification than HMAC (negligible at this scale).
- Must manage a keypair and (in production) rotation. MVP uses a single static key; rotation is
  noted but not built.

## Related

[ADR-0002](0002-jwt-embedded-entitlements-offline-validation.md),
[ADR-0001](0001-centralize-authentication-local-authorization.md).
