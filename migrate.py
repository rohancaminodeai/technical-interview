"""Backfill one tenant's local users into the central IdP (SPEC §7).

This is the runnable core of the migration strategy (ADR-0005): import legacy
local accounts into the IdP, grant the tenant entitlement, and stamp idp_sub
back onto the local row so the tenant can resolve the global identity. Designed
to be idempotent so it can be run repeatedly during a phased, no-downtime rollout.

Usage:
    python migrate.py --tenant tenant_a \
        --tenant-db data/tenant_a.sqlite --idp-db data/idp.sqlite
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from auth_service import store as idp_store  # noqa: E402
from tenant_service import store as tenant_store  # noqa: E402

DEFAULT_ROLES = ["member"]


def migrate_tenant(
    *, tenant_id: str, tenant_db: str, idp_db: str, roles: list[str] | None = None
) -> dict:
    """Migrate every local user into the IdP. Returns {imported, linked, skipped}.

    - imported: global identities newly created in the IdP this run.
    - linked:   local rows newly stamped with idp_sub this run.
    - skipped:  local rows already linked (idp_sub set) — left untouched.

    Idempotent: re-running skips already-linked rows and dedupes identities +
    entitlements by email, so no duplicates and no relinking. Rows with no email
    are ignored (nothing to key a global identity on).
    """
    roles = roles or DEFAULT_ROLES
    imported = linked = skipped = 0

    tconn = tenant_store.connect(tenant_db)
    iconn = idp_store.connect(idp_db)
    try:
        rows = tconn.execute("SELECT id, idp_sub, email, password_hash FROM users").fetchall()
        for row in rows:
            if row["idp_sub"]:
                skipped += 1
                continue
            if not row["email"]:
                continue  # cannot create a global identity without an email

            sub, created = idp_store.upsert_identity(
                iconn, row["email"], row["password_hash"] or ""
            )
            if created:
                imported += 1
            idp_store.upsert_entitlement(iconn, sub, tenant_id, roles)

            tconn.execute("UPDATE users SET idp_sub = ? WHERE id = ?", (sub, row["id"]))
            tconn.commit()
            linked += 1
    finally:
        tconn.close()
        iconn.close()

    return {"imported": imported, "linked": linked, "skipped": skipped}


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill a tenant's users into the IdP")
    parser.add_argument("--tenant", required=True, help="tenant id, e.g. tenant_a")
    parser.add_argument("--tenant-db", required=True, help="path to the tenant's SQLite DB")
    parser.add_argument("--idp-db", required=True, help="path to the IdP SQLite DB")
    args = parser.parse_args()

    # Ensure both schemas exist (safe no-op if already initialized).
    idp_store.init_db(idp_store.connect(args.idp_db))
    tenant_store.init_db(tenant_store.connect(args.tenant_db))

    summary = migrate_tenant(
        tenant_id=args.tenant, tenant_db=args.tenant_db, idp_db=args.idp_db
    )
    print(
        f"migrated {args.tenant}: "
        f"imported={summary['imported']} linked={summary['linked']} "
        f"skipped={summary['skipped']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
