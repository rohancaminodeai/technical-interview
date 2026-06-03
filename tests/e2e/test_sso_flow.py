"""End-to-end assertions against the live 3-service Docker stack.

This is the demo flow as tests (SPEC §5, plan Part 2): log in once at the central
auth service, then prove the token is honored or rejected by each tenant exactly
per the entitlements — including the cross-tenant 403 isolation invariant.
"""
import httpx
import pytest


def _get(url, path, token):
    return httpx.get(url + path, headers={"Authorization": f"Bearer {token}"}, timeout=5)


@pytest.fixture
def alice_token(login):
    resp = login("alice@example.com", "alice-pw")
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def bob_token(login):
    resp = login("bob@example.com", "bob-pw")
    assert resp.status_code == 200
    return resp.json()["access_token"]


# --- login (auth service) -------------------------------------------------

def test_login_returns_bearer_token(login):
    body = login("alice@example.com", "alice-pw").json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 900
    assert body["access_token"].count(".") == 2  # header.payload.signature


def test_bad_credentials_are_401(login):
    assert login("alice@example.com", "nope").status_code == 401
    assert login("ghost@example.com", "whatever").status_code == 401


# --- single token, multiple tenants + isolation ---------------------------

def test_alice_reaches_her_tenant(stack, alice_token):
    resp = _get(stack["tenant_a"], "/data", alice_token)
    assert resp.status_code == 200
    assert resp.json()["tenant"] == "tenant_a"


def test_alice_token_rejected_by_other_tenant(stack, alice_token):
    # THE isolation invariant: a token not entitled to tenant_b must be refused.
    resp = _get(stack["tenant_b"], "/data", alice_token)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "not entitled"


def test_one_login_reaches_both_entitled_tenants(stack, bob_token):
    a = _get(stack["tenant_a"], "/data", bob_token)
    b = _get(stack["tenant_b"], "/data", bob_token)
    assert a.status_code == 200 and b.status_code == 200
    # Each tenant serves ONLY its own rows, even for a multi-tenant token.
    assert a.json()["tenant"] == "tenant_a"
    assert b.json()["tenant"] == "tenant_b"
    assert [i["label"] for i in a.json()["items"]] == ["bob's tenant_a record"]
    assert [i["label"] for i in b.json()["items"]] == ["bob's tenant_b record"]


def test_me_resolves_local_identity(stack, bob_token):
    me = _get(stack["tenant_a"], "/me", bob_token).json()
    assert me["tenant"] == "tenant_a"
    assert me["email"] == "bob@example.com"
    assert me["roles"] == ["member"]
    assert me["idp_sub"].startswith("u_")


# --- negative token checks ------------------------------------------------

def test_missing_token_is_401(stack):
    assert httpx.get(stack["tenant_a"] + "/data", timeout=5).status_code == 401


def test_tampered_token_is_401(stack, alice_token):
    header, payload, sig = alice_token.split(".")
    tampered = f"{header}.{payload}.{sig[:-3]}xyz"
    resp = _get(stack["tenant_a"], "/data", tampered)
    assert resp.status_code == 401


def test_token_minted_for_wrong_audience_is_rejected(stack):
    # A homemade RS256 token (different key, wrong issuer) must not be trusted.
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import jwt as pyjwt
    import time

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    forged = pyjwt.encode(
        {"iss": "https://evil", "aud": "platform-tenants", "sub": "u_x",
         "iat": int(time.time()), "exp": int(time.time()) + 900,
         "entitlements": {"tenant_a": ["admin"]}},
        pem, algorithm="RS256", headers={"kid": "53e38e5dbe91e579"},
    )
    assert _get(stack["tenant_a"], "/data", forged).status_code == 401
