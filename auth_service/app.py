"""Central auth service / IdP (SPEC §4).

Verifies credentials (the ONLY place this happens) and mints RS256 access tokens
carrying the user's tenant entitlements. Also publishes the public key via JWKS
so tenants validate offline.

`create_app` is a factory so tests can inject a temp DB + ephemeral keys; the
ASGI entrypoint (auth_service/asgi.py) calls it with the on-disk defaults.
"""
import json

import bcrypt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, StringConstraints
from typing_extensions import Annotated

from auth_service import store
from common import jwt_tokens
from common.config import (
    DATA_DIR,
    JWKS_PATH,
    PRIVATE_KEY_PATH,
    TOKEN_TTL_SECONDS,
)

# Precomputed once so the unknown-email path does real bcrypt work and stays
# timing-indistinguishable from a wrong-password attempt (SPEC §4.1).
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt())

NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]


class LoginRequest(BaseModel):
    email: NonEmptyStr
    password: NonEmptyStr


def create_app(*, db_path: str, private_key_pem: str, kid: str, jwks: dict) -> FastAPI:
    app = FastAPI(title="auth-service")

    @app.post("/login")
    def login(req: LoginRequest):
        conn = store.connect(db_path)
        try:
            identity = store.get_identity_by_email(conn, req.email)
            if identity is None:
                # No such user: burn a comparison against a dummy hash so timing
                # doesn't reveal whether the email exists, then fail identically.
                bcrypt.checkpw(req.password.encode(), _DUMMY_HASH)
                raise HTTPException(status_code=401, detail="invalid credentials")

            if not bcrypt.checkpw(req.password.encode(), identity["password_hash"].encode()):
                raise HTTPException(status_code=401, detail="invalid credentials")

            entitlements = store.get_entitlements(conn, identity["sub"])
        finally:
            conn.close()

        token = jwt_tokens.mint(
            sub=identity["sub"],
            email=identity["email"],
            entitlements=entitlements,
            private_key_pem=private_key_pem,
            kid=kid,
        )
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
        }

    @app.get("/.well-known/jwks.json")
    def jwks_document():
        return jwks

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app


def build_default_app() -> FastAPI:
    """Wire create_app from on-disk keys + DB (used by the ASGI entrypoint)."""
    jwks = json.loads(JWKS_PATH.read_text())
    return create_app(
        db_path=str(DATA_DIR / "idp.sqlite"),
        private_key_pem=PRIVATE_KEY_PATH.read_text(),
        kid=jwks["keys"][0]["kid"],
        jwks=jwks,
    )
