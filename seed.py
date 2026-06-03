"""Seed deterministic demo data so the stack is reproducible from scratch.

Creates the IdP identities + entitlements and the two tenant DBs (local users
linked to their global identity, plus a per-tenant data row). Wipes any existing
demo DBs first so every `make up` starts from the same known state.

Demo users (the story the demo.sh / e2e tell):
  alice  — entitled to tenant_a ONLY  → proves isolation (A 200, B 403)
  bob    — entitled to BOTH tenants   → proves one login, many tenants (A & B 200)
"""
import bcrypt

from auth_service import store as idp_store
from common.config import DATA_DIR
from tenant_service import store as tenant_store

DEMO_USERS = {
    "alice@example.com": {
        "password": "alice-pw",
        "tenants": {"tenant_a": ["member"]},
    },
    "bob@example.com": {
        "password": "bob-pw",
        "tenants": {"tenant_a": ["member"], "tenant_b": ["admin"]},
    },
}

TENANTS = ("tenant_a", "tenant_b")


def seed() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    idp_db = DATA_DIR / "idp.sqlite"
    tenant_dbs = {t: DATA_DIR / f"{t}.sqlite" for t in TENANTS}

    # Reset for a clean, deterministic demo state.
    for path in [idp_db, *tenant_dbs.values()]:
        path.unlink(missing_ok=True)

    # --- IdP: identities + entitlements ---
    idp = idp_store.connect(str(idp_db))
    idp_store.init_db(idp)
    subs: dict[str, str] = {}
    for email, info in DEMO_USERS.items():
        pw_hash = bcrypt.hashpw(info["password"].encode(), bcrypt.gensalt()).decode()
        sub, _ = idp_store.upsert_identity(idp, email, pw_hash)
        subs[email] = sub
        for tenant, roles in info["tenants"].items():
            idp_store.upsert_entitlement(idp, sub, tenant, roles)
    idp.close()

    # --- Tenants: local users (linked) + data ---
    for tenant, db in tenant_dbs.items():
        conn = tenant_store.connect(str(db))
        tenant_store.init_db(conn)
        for email, info in DEMO_USERS.items():
            if tenant not in info["tenants"]:
                continue  # not entitled here → no local row (also yields 403 at step 5)
            conn.execute(
                "INSERT INTO users (idp_sub, email, password_hash) VALUES (?, ?, ?)",
                (subs[email], email, "legacy-unused"),
            )
            handle = email.split("@")[0]
            conn.execute(
                "INSERT INTO data_items (owner_email, label) VALUES (?, ?)",
                (email, f"{handle}'s {tenant} record"),
            )
        conn.commit()
        conn.close()

    print(f"seeded IdP ({len(DEMO_USERS)} identities) + tenants {', '.join(TENANTS)}")
    for email, info in DEMO_USERS.items():
        print(f"  {email} / {info['password']}  ->  {list(info['tenants'])}")


if __name__ == "__main__":
    seed()
