---
name: review-changes
description: >-
  Review the uncommitted git diff (or a named commit/branch range) of this
  FastAPI + JWT (RS256) authentication prototype for correctness bugs, security
  issues, and reuse/simplification cleanups. Use this skill whenever the user
  asks to "review", "code review", "check my changes", "look over the diff",
  "did I break anything", or wants feedback before committing/pushing — even if
  they don't say the words "code review". This is an auth/identity codebase, so
  treat token validation, key handling, and tenant isolation as first-class
  concerns.
---

# Review Changes

Review the current changes in this repository and report correctness bugs,
security issues, and cleanup opportunities. The goal is a focused, trustworthy
review — every finding should be something a reasonable engineer would act on,
not noise.

## What to review

By default, review the **uncommitted working-tree changes**. If the user names
a commit, branch, or range (e.g. "review the last commit", "review against
main"), scope to that instead.

```bash
# Default: staged + unstaged changes vs HEAD
git diff HEAD

# What's changed at a glance
git diff --stat HEAD

# Untracked files aren't in `git diff` — list them too
git status --porcelain
```

Read the **full content** of each changed file, not just the diff hunks. A diff
hides the surrounding function, the imports, and the call sites — and most real
bugs live in that context (a renamed field, a now-dead branch, a missing await).
Use the diff to find *where* to look, then read the file to *understand* it.

## How to think about this codebase

Read [SPEC.md](../../../SPEC.md) if you haven't — it is the source of truth, and
"the document wins" when behavior disagrees. This is a centralized-auth /
local-authorization system: `auth_service` issues RS256 JWTs, tenant services
validate them offline against JWKS. That design implies a specific threat model.
When reviewing changes that touch auth, weigh them against these:

- **Algorithm pinning** — token verification must pin to `["RS256"]`. Accepting
  `alg: none`, allowing HS256 with the public key as the secret, or trusting the
  token header's `alg` is a critical vulnerability, not a style nit.
- **Claim validation** — `iss`, `aud`, `exp`, and `kid` must actually be
  checked, not just decoded. A token that validates without checking `aud` lets
  a token minted for tenant A be replayed at tenant B.
- **Key handling** — private keys must never be logged, returned in a response,
  or committed. The public JWKS endpoint must expose only public material.
- **Tenant isolation** — a request authenticated for one tenant must not read or
  mutate another tenant's data. Check that `tenant_id` / `idp_sub` scoping is
  applied to every query, not assumed.
- **Password handling** — credentials are verified only in `auth_service` via
  bcrypt; watch for plaintext comparison, missing constant-time checks, or
  credentials crossing into tenant services.

Not every change touches auth. For a change to docs, tests, or config, skip the
threat model and just check it does what it claims.

## Finding bugs

Look for defects that would actually bite: logic that doesn't match the SPEC or
the function's stated intent, mishandled errors and edge cases (empty input,
expired token, missing key, clock skew), off-by-one and boundary mistakes,
incorrect async/await usage, resource leaks, and mutable state shared across
requests. Prefer a few high-confidence findings over a long list of maybes — a
review the user can trust is worth more than an exhaustive one they have to
re-verify.

For each finding, confirm it's real before reporting it. Trace the data flow or
construct the concrete input that triggers it. If you can't convince yourself,
either say so explicitly ("possible, unverified") or drop it.

## Cleanups (lower priority)

After correctness and security, note reuse/simplification wins: duplicated logic
that already exists in [common/](../../../common/), dead code, needless
complexity, and inconsistency with patterns used elsewhere in the repo. Keep
these brief and clearly separated from bugs — they're suggestions, not blockers.

## Report format

Lead with a one-line verdict, then group findings by severity. Skip empty
sections. Reference every finding by `file:line` so it's clickable.

```markdown
## Review: <what was reviewed> — <N> findings

**Verdict:** <one line — e.g. "Safe to commit after fixing the aud check" or "Looks good">

### 🔴 Critical / Security
- **[file.py:42](path#L42)** — <what's wrong, why it matters, and the concrete trigger or fix>

### 🟡 Correctness
- **[file.py:88](path#L88)** — <...>

### 🔵 Cleanup
- **[file.py:10](path#L10)** — <...>
```

If there are no findings, say so plainly and state what you checked — don't pad
the report. A clean review is a valid result.
