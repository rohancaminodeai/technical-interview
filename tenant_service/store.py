"""Tenant-local persistence: users + data_items (SPEC §6.2).

Each tenant has its OWN database. `users` links a local row to a global identity
via `idp_sub`; `data_items` is the tenant-isolated resource. The tenant never
reads any other tenant's DB — that is the data-isolation guarantee in code.
"""
import sqlite3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    idp_sub       TEXT UNIQUE,          -- link to global identity (NULL until migrated)
    email         TEXT NOT NULL,
    password_hash TEXT                  -- legacy local hash; unused once idp_sub set
);
CREATE TABLE IF NOT EXISTS data_items (
    id          INTEGER PRIMARY KEY,
    owner_email TEXT NOT NULL,
    label       TEXT NOT NULL
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    conn.commit()


def get_user_by_idp_sub(conn: sqlite3.Connection, idp_sub: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, idp_sub, email, password_hash FROM users WHERE idp_sub = ?",
        (idp_sub,),
    ).fetchone()


def list_items_for_owner(conn: sqlite3.Connection, owner_email: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, label FROM data_items WHERE owner_email = ? COLLATE NOCASE ORDER BY id",
        (owner_email,),
    ).fetchall()


def provision_user(
    conn: sqlite3.Connection, idp_sub: str, email: str, tenant_id: str
) -> tuple[sqlite3.Row, bool]:
    """Create the local user row for a global identity (JIT provisioning).

    Idempotent on idp_sub: if the row already exists it is returned untouched.
    On first provision a starter data_item is added so /data shows something.
    Returns (user_row, created).
    """
    existing = get_user_by_idp_sub(conn, idp_sub)
    if existing is not None:
        return existing, False
    conn.execute(
        "INSERT INTO users (idp_sub, email, password_hash) VALUES (?, ?, NULL)",
        (idp_sub, email),
    )
    handle = email.split("@")[0]
    conn.execute(
        "INSERT INTO data_items (owner_email, label) VALUES (?, ?)",
        (email, f"{handle}'s {tenant_id} record"),
    )
    conn.commit()
    return get_user_by_idp_sub(conn, idp_sub), True
