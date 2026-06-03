"""TDD for the auth service: POST /login and the JWKS endpoint (SPEC §4)."""
import bcrypt
import pytest
from fastapi.testclient import TestClient

from auth_service import store
from auth_service.app import create_app
from common.jwt_tokens import verify

PASSWORD = "s3cret-pw"


@pytest.fixture
def client(keypair, tmp_path):
    """Auth app backed by a temp IdP DB seeded with two users:
    alice (entitled to tenant_a as member) and bob (no entitlements).
    """
    db_path = str(tmp_path / "idp.sqlite")
    conn = store.connect(db_path)
    store.init_db(conn)
    pw_hash = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt()).decode()
    alice, _ = store.upsert_identity(conn, "alice@example.com", pw_hash)
    store.upsert_entitlement(conn, alice, "tenant_a", ["member"])
    store.upsert_identity(conn, "bob@example.com", pw_hash)  # no entitlements
    conn.close()

    app = create_app(
        db_path=db_path,
        private_key_pem=keypair.private_pem,
        kid=keypair.kid,
        jwks=keypair.jwks,
    )
    return TestClient(app), keypair


# --- POST /login ----------------------------------------------------------

def test_login_success_returns_bearer_token(client):
    tc, kp = client
    resp = tc.post("/login", json={"email": "alice@example.com", "password": PASSWORD})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 900
    claims = verify(body["access_token"], kp.jwks)
    assert claims["sub"].startswith("u_")
    assert claims["email"] == "alice@example.com"
    assert claims["entitlements"] == {"tenant_a": ["member"]}


def test_login_wrong_password_is_401(client):
    tc, _ = client
    resp = tc.post("/login", json={"email": "alice@example.com", "password": "wrong"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid credentials"


def test_login_unknown_email_is_indistinguishable_401(client):
    tc, _ = client
    resp = tc.post("/login", json={"email": "nobody@example.com", "password": PASSWORD})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid credentials"


def test_login_missing_password_is_422(client):
    tc, _ = client
    assert tc.post("/login", json={"email": "alice@example.com"}).status_code == 422


def test_login_empty_email_is_422(client):
    tc, _ = client
    resp = tc.post("/login", json={"email": "", "password": PASSWORD})
    assert resp.status_code == 422


def test_login_user_with_no_entitlements_still_succeeds(client):
    tc, kp = client
    resp = tc.post("/login", json={"email": "bob@example.com", "password": PASSWORD})
    assert resp.status_code == 200
    claims = verify(resp.json()["access_token"], kp.jwks)
    assert claims["entitlements"] == {}


def test_login_email_match_is_case_insensitive(client):
    tc, _ = client
    resp = tc.post("/login", json={"email": "ALICE@example.com", "password": PASSWORD})
    assert resp.status_code == 200


# --- GET /.well-known/jwks.json ------------------------------------------

def test_jwks_endpoint_publishes_public_key(client):
    tc, kp = client
    resp = tc.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    jwks = resp.json()
    assert jwks["keys"][0]["kid"] == kp.kid
    assert jwks["keys"][0]["alg"] == "RS256"
    assert jwks["keys"][0]["kty"] == "RSA"
