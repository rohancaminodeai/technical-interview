"""Tenant workload service (SPEC §5).

Never authenticates. Validates the bearer token offline against the cached JWKS,
enforces the entitlement + local-user checks in the normative order, then serves
only this tenant's own data. The validation order IS the security contract: the
first failing step decides the status code, and the entitlement check (403) runs
before any tenant data is queried — that is the isolation invariant.

`create_app` is a factory so tests can inject a tenant id, JWKS, and temp DB; the
ASGI entrypoint (tenant_service/asgi.py) reads those from the environment.
"""
from fastapi import Depends, FastAPI, Header, HTTPException

from common import jwt_tokens
from common.jwt_tokens import ExpiredToken, InvalidToken
from tenant_service import store


def create_app(*, tenant_id: str, jwks: dict, db_path: str) -> FastAPI:
    app = FastAPI(title=f"tenant-service:{tenant_id}")

    def authenticate(authorization: str | None = Header(default=None)) -> dict:
        """Run the SPEC §5.1 pipeline; return {claims, user, roles} on success."""
        # Step 1: header present and well-formed.
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing token")
        token = authorization[len("Bearer ") :].strip()
        if not token:
            raise HTTPException(status_code=401, detail="missing token")

        # Steps 2-4: signature (alg-pinned), expiry/nbf, iss/aud.
        try:
            claims = jwt_tokens.verify(token, jwks)
        except ExpiredToken as exc:
            raise HTTPException(status_code=401, detail=exc.detail) from exc
        except InvalidToken as exc:
            raise HTTPException(status_code=401, detail=exc.detail) from exc

        # Step 5: entitlement for THIS tenant (the isolation invariant) — before any DB read.
        entitlements = claims.get("entitlements", {})
        if tenant_id not in entitlements:
            raise HTTPException(status_code=403, detail="not entitled")

        # Step 6: the global sub resolves to a local user row.
        conn = store.connect(db_path)
        try:
            user = store.get_user_by_idp_sub(conn, claims["sub"])
        finally:
            conn.close()
        if user is None:
            raise HTTPException(status_code=403, detail="no local user")

        return {"claims": claims, "user": user, "roles": entitlements[tenant_id]}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "tenant": tenant_id}

    @app.get("/me")
    def me(ctx: dict = Depends(authenticate)):
        user = ctx["user"]
        return {
            "tenant": tenant_id,
            "idp_sub": user["idp_sub"],
            "local_user_id": user["id"],
            "email": user["email"],
            "roles": ctx["roles"],
        }

    @app.get("/data")
    def data(ctx: dict = Depends(authenticate)):
        user = ctx["user"]
        conn = store.connect(db_path)
        try:
            items = store.list_items_for_owner(conn, user["email"])
        finally:
            conn.close()
        return {
            "tenant": tenant_id,
            "owner": user["email"],
            "items": [{"id": row["id"], "label": row["label"]} for row in items],
        }

    return app
