"""TDD for the tenant service: the normative validation pipeline (SPEC §5).

Covers all six steps and the isolation invariant — a token not naming this
tenant gets 403 at step 5, before any data is touched.
"""
import time

import pytest
from fastapi.testclient import TestClient

from common.config import TOKEN_TTL_SECONDS
from common.jwt_tokens import mint
from tenant_service import store
from tenant_service.app import create_app

ALICE_SUB = "u_alice"


def _make_tenant(keypair, tmp_path, tenant_id):
    """Build a tenant app seeded with alice (linked) + her data row."""
    db_path = str(tmp_path / f"{tenant_id}.sqlite")
    conn = store.connect(db_path)
    store.init_db(conn)
    conn.execute(
        "INSERT INTO users (idp_sub, email, password_hash) VALUES (?, ?, ?)",
        (ALICE_SUB, "alice@example.com", "legacy"),
    )
    conn.execute(
        "INSERT INTO data_items (owner_email, label) VALUES (?, ?)",
        ("alice@example.com", f"{tenant_id} record"),
    )
    conn.commit()
    conn.close()
    app = create_app(tenant_id=tenant_id, jwks=keypair.jwks, db_path=db_path)
    return TestClient(app)


@pytest.fixture
def tenant_a(keypair, tmp_path):
    return _make_tenant(keypair, tmp_path, "tenant_a")


@pytest.fixture
def tenant_b(keypair, tmp_path):
    return _make_tenant(keypair, tmp_path, "tenant_b")


def _token(keypair, entitlements, sub=ALICE_SUB, **overrides):
    return mint(
        sub=sub,
        email="alice@example.com",
        entitlements=entitlements,
        private_key_pem=keypair.private_pem,
        kid=keypair.kid,
        **overrides,
    )


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# --- healthz (no auth) ----------------------------------------------------

def test_healthz_needs_no_auth(tenant_a):
    resp = tenant_a.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "tenant": "tenant_a"}


# --- step 1: Authorization header ----------------------------------------

def test_missing_header_is_401(tenant_a):
    resp = tenant_a.get("/me")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing token"


def test_malformed_header_is_401(tenant_a):
    resp = tenant_a.get("/me", headers={"Authorization": "Token abc"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing token"


# --- steps 2-4: signature / expiry / iss-aud -----------------------------

def test_garbage_token_is_401_invalid(tenant_a):
    resp = tenant_a.get("/me", headers=_auth("not.a.token"))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid token"


def test_expired_token_is_401_expired(tenant_a, keypair):
    past = int(time.time()) - TOKEN_TTL_SECONDS - 120
    token = _token(keypair, {"tenant_a": ["member"]}, now=past)
    resp = tenant_a.get("/me", headers=_auth(token))
    assert resp.status_code == 401
    assert resp.json()["detail"] == "token expired"


# --- step 5: entitlement / isolation invariant ---------------------------

def test_entitled_token_resolves_on_me(tenant_a, keypair):
    token = _token(keypair, {"tenant_a": ["member"]})
    resp = tenant_a.get("/me", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant"] == "tenant_a"
    assert body["idp_sub"] == ALICE_SUB
    assert body["email"] == "alice@example.com"
    assert body["roles"] == ["member"]
    assert body["local_user_id"] == 1


def test_token_for_other_tenant_is_403(tenant_b, keypair):
    # Token entitled to tenant_a ONLY, presented to tenant_b → isolation 403.
    token = _token(keypair, {"tenant_a": ["member"]})
    resp = tenant_b.get("/data", headers=_auth(token))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "not entitled"


def test_zero_entitlement_token_is_403(tenant_a, keypair):
    token = _token(keypair, {})
    resp = tenant_a.get("/me", headers=_auth(token))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "not entitled"


# --- step 6: local user mapping ------------------------------------------

def test_entitled_but_no_local_user_is_403(tenant_a, keypair):
    # Entitled centrally, but this sub was never provisioned in the tenant DB.
    token = _token(keypair, {"tenant_a": ["member"]}, sub="u_ghost")
    resp = tenant_a.get("/me", headers=_auth(token))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "no local user"


# --- /data isolation even with a multi-tenant token ----------------------

def test_data_returns_only_this_tenants_rows(tenant_a, tenant_b, keypair):
    token = _token(keypair, {"tenant_a": ["member"], "tenant_b": ["admin"]})

    a = tenant_a.get("/data", headers=_auth(token)).json()
    b = tenant_b.get("/data", headers=_auth(token)).json()

    assert a["tenant"] == "tenant_a"
    assert [i["label"] for i in a["items"]] == ["tenant_a record"]
    assert b["tenant"] == "tenant_b"
    assert [i["label"] for i in b["items"]] == ["tenant_b record"]
    assert a["owner"] == b["owner"] == "alice@example.com"
