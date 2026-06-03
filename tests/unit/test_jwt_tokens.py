"""TDD for the JWT mint/verify core (SPEC §3, §5.1 steps 2-4).

The security-critical surface: claim correctness, RS256 signature, expiry +
clock-skew leeway, and rejection of tampering / algorithm-confusion attacks.
"""
import base64
import hashlib
import hmac
import json
import time

import jwt as pyjwt
import pytest

from common.config import ALGORITHM, AUDIENCE, ISSUER, TOKEN_TTL_SECONDS
from common.jwt_tokens import ExpiredToken, InvalidToken, mint, verify

ENTITLEMENTS = {"tenant_a": ["member"], "tenant_b": ["admin"]}


def _mint(kp, **overrides):
    kwargs = dict(
        sub="u_abc123",
        email="alice@example.com",
        entitlements=ENTITLEMENTS,
        private_key_pem=kp.private_pem,
        kid=kp.kid,
    )
    kwargs.update(overrides)
    return mint(**kwargs)


# --- minting --------------------------------------------------------------

def test_mint_includes_all_required_claims(keypair):
    token = _mint(keypair)
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE
    assert claims["sub"] == "u_abc123"
    assert claims["email"] == "alice@example.com"
    assert claims["entitlements"] == ENTITLEMENTS
    assert claims["exp"] - claims["iat"] == TOKEN_TTL_SECONDS
    assert "jti" in claims and claims["jti"]


def test_header_pins_rs256_and_carries_kid(keypair):
    token = _mint(keypair)
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == ALGORITHM == "RS256"
    assert header["kid"] == keypair.kid


def test_each_token_has_unique_jti(keypair):
    a = pyjwt.decode(_mint(keypair), options={"verify_signature": False})
    b = pyjwt.decode(_mint(keypair), options={"verify_signature": False})
    assert a["jti"] != b["jti"]


# --- happy-path verification ---------------------------------------------

def test_verify_accepts_a_valid_token(keypair):
    claims = verify(_mint(keypair), keypair.jwks)
    assert claims["sub"] == "u_abc123"
    assert claims["entitlements"] == ENTITLEMENTS


# --- expiry + leeway (SPEC §5.1 step 3) -----------------------------------

def test_verify_rejects_expired_token(keypair):
    past = int(time.time()) - TOKEN_TTL_SECONDS - 120  # expired well beyond leeway
    with pytest.raises(ExpiredToken):
        verify(_mint(keypair, now=past), keypair.jwks)


def test_verify_tolerates_clock_skew_within_leeway(keypair):
    # exp 30s in the past — inside the 60s skew leeway → still accepted.
    almost = int(time.time()) - TOKEN_TTL_SECONDS - 30
    claims = verify(_mint(keypair, now=almost), keypair.jwks)
    assert claims["sub"] == "u_abc123"


def test_verify_rejects_not_yet_valid_token(keypair):
    # Hand-craft a token with nbf far in the future (mint() never sets nbf).
    future = int(time.time()) + 3600
    forged = pyjwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "u_x", "iat": future,
         "exp": future + 900, "nbf": future, "entitlements": {}},
        keypair.private_pem, algorithm="RS256", headers={"kid": keypair.kid},
    )
    with pytest.raises(InvalidToken):
        verify(forged, keypair.jwks)


# --- signature integrity --------------------------------------------------

def test_verify_rejects_tampered_payload(keypair):
    token = _mint(keypair)
    header, payload, sig = token.split(".")
    bad = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB")
    with pytest.raises(InvalidToken):
        verify(f"{header}.{bad}.{sig}", keypair.jwks)


def test_verify_rejects_token_signed_by_another_key(keypair, other_keypair):
    # Correct kid in the header, but signed by a different private key.
    forged = pyjwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "u_x",
         "iat": int(time.time()), "exp": int(time.time()) + 900, "entitlements": {}},
        other_keypair.private_pem, algorithm="RS256", headers={"kid": keypair.kid},
    )
    with pytest.raises(InvalidToken):
        verify(forged, keypair.jwks)


# --- algorithm-confusion attacks (highest-priority, SPEC §3.1) ------------

def test_verify_rejects_alg_none(keypair):
    forged = pyjwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "u_x",
         "iat": int(time.time()), "exp": int(time.time()) + 900, "entitlements": {}},
        key="", algorithm="none", headers={"kid": keypair.kid},
    )
    with pytest.raises(InvalidToken):
        verify(forged, keypair.jwks)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_verify_rejects_hs256_signed_with_public_key(keypair):
    # Classic RS->HS confusion: attacker HMAC-signs with the public key as secret.
    # PyJWT's encode() refuses to use a PEM key as an HMAC secret, so we forge
    # the token by hand — exactly what an attacker would do — then assert verify
    # rejects it because we pin algorithms=["RS256"].
    header = {"alg": "HS256", "kid": keypair.kid, "typ": "JWT"}
    payload = {"iss": ISSUER, "aud": AUDIENCE, "sub": "u_x",
               "iat": int(time.time()), "exp": int(time.time()) + 900, "entitlements": {}}
    signing_input = (
        _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    )
    sig = hmac.new(keypair.public_pem.encode(), signing_input.encode(), hashlib.sha256).digest()
    forged = signing_input + "." + _b64url(sig)
    with pytest.raises(InvalidToken):
        verify(forged, keypair.jwks)


# --- issuer / audience (SPEC §5.1 step 4) ---------------------------------

def test_verify_rejects_wrong_issuer(keypair):
    forged = pyjwt.encode(
        {"iss": "https://evil.example", "aud": AUDIENCE, "sub": "u_x",
         "iat": int(time.time()), "exp": int(time.time()) + 900, "entitlements": {}},
        keypair.private_pem, algorithm="RS256", headers={"kid": keypair.kid},
    )
    with pytest.raises(InvalidToken):
        verify(forged, keypair.jwks)


def test_verify_rejects_wrong_audience(keypair):
    forged = pyjwt.encode(
        {"iss": ISSUER, "aud": "someone-else", "sub": "u_x",
         "iat": int(time.time()), "exp": int(time.time()) + 900, "entitlements": {}},
        keypair.private_pem, algorithm="RS256", headers={"kid": keypair.kid},
    )
    with pytest.raises(InvalidToken):
        verify(forged, keypair.jwks)


# --- key selection --------------------------------------------------------

def test_verify_rejects_unknown_kid(keypair):
    token = _mint(keypair, kid="not-a-real-kid")
    with pytest.raises(InvalidToken):
        verify(token, keypair.jwks)


def test_verify_rejects_missing_kid(keypair):
    forged = pyjwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "u_x",
         "iat": int(time.time()), "exp": int(time.time()) + 900, "entitlements": {}},
        keypair.private_pem, algorithm="RS256",  # no kid header
    )
    with pytest.raises(InvalidToken):
        verify(forged, keypair.jwks)


def test_verify_rejects_garbage_string(keypair):
    with pytest.raises(InvalidToken):
        verify("this.is.notatoken", keypair.jwks)
