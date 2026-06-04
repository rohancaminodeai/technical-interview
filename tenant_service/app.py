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
from common.web import maybe_enable_cors
from tenant_service import store


def create_app(*, tenant_id: str, jwks: dict, db_path: str) -> FastAPI:
    app = FastAPI(title=f"tenant-service:{tenant_id}")
    maybe_enable_cors(app)

    def verify_and_entitle(authorization: str | None) -> dict:
        """SPEC §5.1 steps 1-5: a valid, unexpired, entitled token for THIS tenant.

        Stops before the local-user lookup so it can back both /me-/data (which
        require provisioning) and /provision (which creates that local user).
        """
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

        return {"claims": claims, "roles": entitlements[tenant_id]}

    def authenticate(authorization: str | None = Header(default=None)) -> dict:
        """Full SPEC §5.1 pipeline; return {claims, user, roles} on success."""
        ctx = verify_and_entitle(authorization)

        # Step 6: the global sub resolves to a local user row.
        conn = store.connect(db_path)
        try:
            user = store.get_user_by_idp_sub(conn, ctx["claims"]["sub"])
        finally:
            conn.close()
        if user is None:
            raise HTTPException(status_code=403, detail="no local user")

        return {"claims": ctx["claims"], "user": user, "roles": ctx["roles"]}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "tenant": tenant_id}

    @app.post("/provision")
    def provision(authorization: str | None = Header(default=None)):
        """JIT-provision the token holder as a local user (demo convenience).

        Requires steps 1-5 (a valid token entitled to this tenant), then creates
        the local `users` row that /me and /data need. Idempotent. This is the
        tenant closing the entitlement-vs-provisioning gap on its own DB.
        """
        ctx = verify_and_entitle(authorization)
        claims = ctx["claims"]
        conn = store.connect(db_path)
        try:
            user, created = store.provision_user(
                conn, claims["sub"], claims["email"], tenant_id
            )
        finally:
            conn.close()
        return {
            "tenant": tenant_id,
            "provisioned": created,  # False if already existed (idempotent)
            "local_user_id": user["id"],
            "email": user["email"],
        }

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
