"""IdP persistence: global identities + entitlements (SPEC §6.1).

A thin wrapper over SQLite. Shared by the auth service (read at login) and by
migrate.py (write during backfill). Email matching is case-insensitive so the
same human is one global identity regardless of how a tenant stored their email.
"""
import json
import sqlite3
import uuid

_SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    sub           TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entitlements (
    sub       TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    roles     TEXT NOT NULL,            -- JSON array
    PRIMARY KEY (sub, tenant_id)
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    conn.commit()


def new_sub() -> str:
    return "u_" + uuid.uuid4().hex


def get_identity_by_email(conn: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT sub, email, password_hash FROM identities WHERE email = ? COLLATE NOCASE",
        (email,),
    ).fetchone()


def upsert_identity(conn: sqlite3.Connection, email: str, password_hash: str) -> tuple[str, bool]:
    """Return (sub, created). Idempotent on email — never creates a duplicate human.

    If the email already exists the stored hash is left untouched (the IdP is
    authoritative once migrated; we don't clobber it on re-runs).
    """
    existing = get_identity_by_email(conn, email)
    if existing is not None:
        return existing["sub"], False
    sub = new_sub()
    conn.execute(
        "INSERT INTO identities (sub, email, password_hash) VALUES (?, ?, ?)",
        (sub, email, password_hash),
    )
    conn.commit()
    return sub, True


def upsert_entitlement(
    conn: sqlite3.Connection, sub: str, tenant_id: str, roles: list[str]
) -> bool:
    """Grant `sub` access to `tenant_id`. Return True if newly created.

    Idempotent: a second grant for the same (sub, tenant_id) is a no-op and keeps
    the existing roles, so re-running migration never relinks or duplicates.
    """
    exists = conn.execute(
        "SELECT 1 FROM entitlements WHERE sub = ? AND tenant_id = ?", (sub, tenant_id)
    ).fetchone()
    if exists:
        return False
    conn.execute(
        "INSERT INTO entitlements (sub, tenant_id, roles) VALUES (?, ?, ?)",
        (sub, tenant_id, json.dumps(roles)),
    )
    conn.commit()
    return True


def get_entitlements(conn: sqlite3.Connection, sub: str) -> dict[str, list[str]]:
    """Return {tenant_id: roles} read fresh from the store (SPEC §4.1)."""
    rows = conn.execute(
        "SELECT tenant_id, roles FROM entitlements WHERE sub = ?", (sub,)
    ).fetchall()
    return {row["tenant_id"]: json.loads(row["roles"]) for row in rows}
