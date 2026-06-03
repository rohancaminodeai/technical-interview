# ADR-0005: Zero-downtime migration via dual-auth, dual-write, per-tenant rollout

- **Status:** Accepted
- **Date:** 2026-06-03
- **Deciders:** Platform / Identity

## Context

~50 existing tenants each have their own local `users` table with their own password hashes.
We must move them to central authentication **without downtime** and **without forcing any
logged-in user to re-authenticate**. We cannot read plaintext passwords, and the same human may
exist as separate rows in multiple tenants.

A big-bang cutover (flip everyone at once) risks a platform-wide auth outage and forced
re-login. Rejected.

## Decision

Migrate incrementally, one tenant at a time, keeping local auth fully working until each tenant
is proven on central auth.

1. **Stand up the IdP** in the identity account. Tenant apps untouched.
2. **Backfill (per tenant):** import `email + password_hash` into the central store (hashes
   imported as-is; lazy-rehash on next central login if schemes differ), dedupe humans by
   **verified email** into one global identity, write the tenant entitlement, and stamp
   `idp_sub` back onto the local row. Idempotent. *(This is what `migrate.py` demonstrates.)*
3. **Dual-auth path:** the tenant app accepts **either** a legacy local session **or** a central
   JWT, behind a per-tenant feature flag.
4. **Dual-write:** during transition, credential/profile changes write to **both** the local
   table and the IdP. The local table stays authoritative until we trust the IdP.
5. **No forced re-auth:** existing PHP sessions remain valid until natural expiry; only *new*
   logins route through central auth. Cut over as sessions drain.
6. **Make IdP authoritative** only after all ~50 tenants are stable; then stop local writes and
   retire local auth last.

**Rollback:** flip the per-tenant flag back to local auth. Because local tables stay intact via
dual-write, rollback is instant and lossless.

**Ordering:** IdP up → backfill + dual-read (low risk, reversible) → enable dual-auth on a pilot
tenant → expand tenant-by-tenant → stop local writes → retire local auth.

## Consequences

**Positive**
- No downtime and no forced re-login — both hard requirements met.
- Per-tenant blast radius; a problem affects one tenant, not all 50.
- Cheap, instant rollback at every step because local auth never leaves until the end.

**Negative / cost**
- A dual-write/dual-auth period adds temporary complexity and must be removed afterward.
- Identity reconciliation is genuinely hard: unverified or mismatched emails can't be silently
  merged — keep them separate and offer account-linking.
- Password-hash heterogeneity requires supporting multiple verifiers during transition.

## Related

[ADR-0001](0001-centralize-authentication-local-authorization.md).
