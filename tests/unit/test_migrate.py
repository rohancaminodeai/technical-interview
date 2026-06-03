"""TDD for migrate.py: backfill a tenant's local users into the IdP (SPEC §7).

The contract that matters: dedupe humans by email, stamp idp_sub back, and be
idempotent — re-running must not duplicate identities/entitlements or relink.
"""
import pytest

from auth_service import store as idp_store
from migrate import migrate_tenant
from tenant_service import store as tenant_store


def _seed_tenant(db_path, rows):
    conn = tenant_store.connect(db_path)
    tenant_store.init_db(conn)
    for email, pw in rows:
        conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw)
        )
    conn.commit()
    conn.close()


def _new_idp(db_path):
    conn = idp_store.connect(db_path)
    idp_store.init_db(conn)
    conn.close()


@pytest.fixture
def dbs(tmp_path):
    tenant_db = str(tmp_path / "tenant_a.sqlite")
    idp_db = str(tmp_path / "idp.sqlite")
    _seed_tenant(tenant_db, [("alice@example.com", "h1"), ("bob@example.com", "h2")])
    _new_idp(idp_db)
    return tenant_db, idp_db


def test_backfill_creates_identities_entitlements_and_links(dbs):
    tenant_db, idp_db = dbs
    summary = migrate_tenant(tenant_id="tenant_a", tenant_db=tenant_db, idp_db=idp_db)
    assert summary == {"imported": 2, "linked": 2, "skipped": 0}

    idp = idp_store.connect(idp_db)
    alice = idp_store.get_identity_by_email(idp, "alice@example.com")
    assert alice is not None
    assert alice["password_hash"] == "h1"  # legacy hash imported as-is
    assert idp_store.get_entitlements(idp, alice["sub"]) == {"tenant_a": ["member"]}

    tdb = tenant_store.connect(tenant_db)
    linked = tdb.execute(
        "SELECT idp_sub FROM users WHERE email = ?", ("alice@example.com",)
    ).fetchone()
    assert linked["idp_sub"] == alice["sub"]


def test_migration_is_idempotent(dbs):
    tenant_db, idp_db = dbs
    first = migrate_tenant(tenant_id="tenant_a", tenant_db=tenant_db, idp_db=idp_db)
    second = migrate_tenant(tenant_id="tenant_a", tenant_db=tenant_db, idp_db=idp_db)

    # Second run: everything already linked → all skipped, nothing imported.
    assert first == {"imported": 2, "linked": 2, "skipped": 0}
    assert second == {"imported": 0, "linked": 0, "skipped": 2}

    idp = idp_store.connect(idp_db)
    count = idp.execute("SELECT COUNT(*) AS c FROM identities").fetchone()["c"]
    assert count == 2  # no duplicate identities


def test_same_email_across_tenants_dedupes_to_one_identity(tmp_path):
    idp_db = str(tmp_path / "idp.sqlite")
    _new_idp(idp_db)
    a_db = str(tmp_path / "tenant_a.sqlite")
    b_db = str(tmp_path / "tenant_b.sqlite")
    _seed_tenant(a_db, [("carol@example.com", "ha")])
    _seed_tenant(b_db, [("carol@example.com", "hb")])  # same human, different tenant

    migrate_tenant(tenant_id="tenant_a", tenant_db=a_db, idp_db=idp_db)
    s = migrate_tenant(tenant_id="tenant_b", tenant_db=b_db, idp_db=idp_db)

    idp = idp_store.connect(idp_db)
    count = idp.execute("SELECT COUNT(*) AS c FROM identities").fetchone()["c"]
    assert count == 1  # one global identity for carol
    carol = idp_store.get_identity_by_email(idp, "carol@example.com")
    # Entitled to BOTH tenants under the single identity.
    assert idp_store.get_entitlements(idp, carol["sub"]) == {
        "tenant_a": ["member"],
        "tenant_b": ["member"],
    }
    # Second tenant reused the existing identity → not re-imported, but linked.
    assert s == {"imported": 0, "linked": 1, "skipped": 0}


def test_rows_without_usable_email_are_ignored(tmp_path):
    # Schema enforces email NOT NULL, so the representable degenerate case is an
    # empty-string email — there's nothing to key a global identity on.
    idp_db = str(tmp_path / "idp.sqlite")
    _new_idp(idp_db)
    tenant_db = str(tmp_path / "tenant_a.sqlite")
    conn = tenant_store.connect(tenant_db)
    tenant_store.init_db(conn)
    conn.execute("INSERT INTO users (email, password_hash) VALUES ('', 'x')")
    conn.commit()
    conn.close()

    summary = migrate_tenant(tenant_id="tenant_a", tenant_db=tenant_db, idp_db=idp_db)
    assert summary == {"imported": 0, "linked": 0, "skipped": 0}
