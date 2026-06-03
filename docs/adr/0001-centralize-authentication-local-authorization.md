# ADR-0001: Centralize authentication, keep authorization local

- **Status:** Accepted
- **Date:** 2026-06-03
- **Deciders:** Platform / Identity

## Context

Each tenant authenticates users against its own MySQL `users` table and stores sessions in its
PHP/Apache container. A person working across N customer sites therefore has N accounts, N
passwords, and N login URLs. We want one login that reaches every entitled tenant — without
collapsing tenant data isolation.

The naive options:
- **A. One shared database for all tenants** — breaks the per-account isolation model entirely;
  a query bug leaks across tenants. Rejected.
- **B. Central service owns *everything* (authn + authz + data)** — turns the IdP into a
  blast-radius-of-the-whole-platform monolith and couples every request to it. Rejected.
- **C. Central authentication, local authorization** — chosen.

## Decision

Split identity along the authn/authz seam:

- A **central Identity Provider (IdP)** owns *authentication*: credentials, password
  verification, MFA, and the canonical record of *which tenants a user may access*
  (entitlements).
- Each **tenant** owns *authorization*: it validates the IdP-issued credential, then resolves
  the global identity to a **local** user row (`idp_sub` column) and applies its own local
  roles/permissions against its own data.

The IdP proves *who you are*; the tenant decides *what you can do*.

## Consequences

**Positive**
- One credential, many tenants — solves the core problem.
- Tenant data isolation is preserved: tenants still query only their own DB and never trust each
  other.
- Tenant authorization logic is largely unchanged (it keeps its `users` table + local roles).
- Blast radius is bounded: the IdP holds auth secrets, never tenant business data.

**Negative / cost**
- A new critical service (the IdP) and a new account to operate and secure.
- Need a mapping (`idp_sub`) between global identity and each local user row.
- Entitlement data now has a source of truth (IdP) that must stay reconciled with local state.

## Related

[ADR-0002](0002-jwt-embedded-entitlements-offline-validation.md) (how the credential carries
entitlements), [ADR-0004](0004-availability-fail-open-closed.md) (what happens if the IdP is
down).
