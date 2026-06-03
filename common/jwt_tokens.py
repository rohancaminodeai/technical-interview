"""Mint and verify the platform's access tokens (SPEC §3, §5.1 steps 2-4).

`mint` runs in the auth service (holds the private key). `verify` runs in every
tenant service (holds only the public JWKS) and is the security-critical path:
it pins the algorithm to RS256, validates exp/nbf/iss/aud, and selects the
signing key by `kid`. It performs steps 2-4 of the tenant validation pipeline;
entitlement (step 5) and local-user (step 6) checks live in the tenant service.
"""
import time
import uuid

import jwt as pyjwt

from common.config import (
    ALGORITHM,
    AUDIENCE,
    CLOCK_SKEW_LEEWAY_SECONDS,
    ISSUER,
    TOKEN_TTL_SECONDS,
)


class TokenError(Exception):
    """Base for verification failures. `detail` is the client-facing 401 reason."""

    detail = "invalid token"


class InvalidToken(TokenError):
    """Bad signature, wrong alg, iss/aud mismatch, unknown kid, malformed, etc."""

    detail = "invalid token"


class ExpiredToken(TokenError):
    """`exp` is in the past (beyond the skew leeway)."""

    detail = "token expired"


def mint(
    *,
    sub: str,
    email: str,
    entitlements: dict,
    private_key_pem: str,
    kid: str,
    ttl: int = TOKEN_TTL_SECONDS,
    now: int | None = None,
) -> str:
    """Sign an RS256 access token carrying the user's tenant entitlements.

    `now` is injectable so tests can mint already-expired tokens deterministically.
    """
    issued = int(time.time()) if now is None else now
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": sub,
        "iat": issued,
        "exp": issued + ttl,
        "jti": uuid.uuid4().hex,
        "email": email,
        "entitlements": entitlements,
    }
    return pyjwt.encode(payload, private_key_pem, algorithm=ALGORITHM, headers={"kid": kid})


def _select_key(jwks: dict, kid: str | None):
    """Return the public key from the JWKS whose `kid` matches the token header."""
    if not kid:
        raise InvalidToken("missing key id")
    for jwk in jwks.get("keys", []):
        if jwk.get("kid") == kid:
            return pyjwt.PyJWK.from_dict(jwk).key
    raise InvalidToken("unknown key id")


def verify(token: str, jwks: dict, *, leeway: int = CLOCK_SKEW_LEEWAY_SECONDS) -> dict:
    """Verify signature + standard claims and return the decoded claims.

    Raises ExpiredToken on expiry, InvalidToken on every other failure. Pinning
    `algorithms=[ALGORITHM]` is what defeats `alg:none` and RS->HS confusion.
    """
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError as exc:
        raise InvalidToken("malformed token") from exc

    key = _select_key(jwks, header.get("kid"))

    try:
        return pyjwt.decode(
            token,
            key=key,
            algorithms=[ALGORITHM],  # pin RS256 — rejects none / HS256 confusion
            issuer=ISSUER,
            audience=AUDIENCE,
            leeway=leeway,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise ExpiredToken("token expired") from exc
    except pyjwt.PyJWTError as exc:
        raise InvalidToken("invalid token") from exc
