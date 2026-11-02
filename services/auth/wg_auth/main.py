"""Микросервис аутентификации и верификации.

Внутренний API (доступен только шлюзу и микросервису безопасности,
что обеспечивается сетевыми политиками Kubernetes):
  POST /internal/login   — проверка пароля и выпуск привязанного токена;
  POST /internal/verify  — проверка токена и его привязки;
  POST /internal/revoke  — отзыв токена (прекращение сессии);
  GET  /healthz, /readyz — пробы Kubernetes.
"""
import logging
from datetime import datetime, timezone

import httpx
from fastapi import BackgroundTasks, FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import (Boolean, Column, DateTime, Integer, MetaData, String,
                        Table, insert, select, update)
from sqlalchemy.engine import Engine

from wg_common.audit import emit_sync, make_event
from wg_common.db import db_alive, init_schema, make_engine
from wg_common.settings import env, env_int

from .passwords import hash_password, verify_password
from .tokens import TokenError, check_token, issue_token

log = logging.getLogger("wg_auth")
SERVICE = "auth"

metadata = MetaData()
users = Table(
    "wg_users", metadata,
    Column("username", String(64), primary_key=True),
    Column("password_hash", String(256), nullable=False),
    Column("role", String(16), nullable=False, default="user"),
)
sessions = Table(
    "wg_sessions", metadata,
    Column("jti", String(32), primary_key=True),
    Column("username", String(64), nullable=False, index=True),
    Column("cert_fp", String(64), nullable=False),
    Column("bssid", String(17)),
    Column("hops", Integer),
    Column("issued_at", DateTime, nullable=False),
    Column("expires_at", DateTime, nullable=False),
    Column("revoked", Boolean, nullable=False, default=False),
    Column("revoke_reason", String(64)),
)


class LoginIn(BaseModel):
    username: str
    password: str
    cert_fp: str
    bssid: str | None = None
    hops: int | None = None
    client_ip: str | None = None


class VerifyIn(BaseModel):
    token: str
    cert_fp: str | None = None
    client_ip: str | None = None


class RevokeIn(BaseModel):
    jti: str
    reason: str = "security_block"


def seed_users(engine: Engine, spec: str | None) -> None:
    """Создаёт учётные записи из строки "user:pass:role;user2:pass2:role"."""
    if not spec:
        return
    with engine.begin() as conn:
        for item in filter(None, spec.split(";")):
            username, password, role = item.split(":", 2)
            exists = conn.execute(select(users.c.username)
                                  .where(users.c.username == username)).first()
            if not exists:
                conn.execute(insert(users).values(
                    username=username, password_hash=hash_password(password), role=role))


def create_app(engine: Engine | None = None, http: httpx.Client | None = None) -> FastAPI:
    engine = engine or make_engine()
    http = http or httpx.Client()
    secret = env("JWT_SECRET", required=True)
    if len(secret.encode()) < 32:
        # RFC 7518, п. 3.2: ключ HS256 должен быть не короче 256 бит
        raise RuntimeError("JWT_SECRET короче 32 байт")
    token_ttl = env_int("TOKEN_TTL_SECONDS", 900)

    init_schema(engine, metadata)
    seed_users(engine, env("SEED_USERS"))

    app = FastAPI(title="WiFi-Guard: аутентификация и верификация")

    def audit(bg: BackgroundTasks, event_type: str, severity: str, **fields):
        bg.add_task(emit_sync, http, make_event(SERVICE, event_type, severity, **fields))

    @app.post("/internal/login")
    def login(body: LoginIn, bg: BackgroundTasks):
        with engine.connect() as conn:
            row = conn.execute(select(users).where(users.c.username == body.username)).first()
        if row is None or not verify_password(body.password, row.password_hash):
            audit(bg, "AUTH_FAILURE", "warning", username=body.username,
                  client_ip=body.client_ip, bssid=body.bssid, reason="bad_credentials")
            return JSONResponse({"detail": "invalid credentials"}, status_code=401)

        token, claims = issue_token(secret, row.username, row.role, body.cert_fp,
                                    body.bssid, body.hops, token_ttl)
        with engine.begin() as conn:
            conn.execute(insert(sessions).values(
                jti=claims["jti"], username=row.username, cert_fp=body.cert_fp,
                bssid=body.bssid, hops=body.hops,
                issued_at=datetime.fromtimestamp(claims["iat"], timezone.utc).replace(tzinfo=None),
                expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc).replace(tzinfo=None),
                revoked=False))
        audit(bg, "LOGIN_SUCCESS", "info", username=row.username, jti=claims["jti"],
              client_ip=body.client_ip, bssid=body.bssid)
        return {"access_token": token, "token_type": "Bearer", "expires_in": token_ttl}

    @app.post("/internal/verify")
    def verify(body: VerifyIn, bg: BackgroundTasks):
        try:
            claims = check_token(secret, body.token, body.cert_fp)
            with engine.connect() as conn:
                sess = conn.execute(select(sessions.c.revoked)
                                    .where(sessions.c.jti == claims["jti"])).first()
            if sess is None:
                raise TokenError("unknown_session")
            if sess.revoked:
                raise TokenError("session_revoked")
        except TokenError as err:
            audit(bg, "AUTH_FAILURE", "warning", client_ip=body.client_ip,
                  reason=err.reason, scenario="C2" if err.reason == "binding_mismatch" else None)
            return JSONResponse({"valid": False, "reason": err.reason}, status_code=401)
        return {"valid": True, "sub": claims["sub"], "role": claims["role"],
                "jti": claims["jti"], "ctx": claims.get("ctx") or {}}

    @app.post("/internal/revoke")
    def revoke(body: RevokeIn, bg: BackgroundTasks):
        with engine.begin() as conn:
            result = conn.execute(update(sessions).where(sessions.c.jti == body.jti)
                                  .values(revoked=True, revoke_reason=body.reason))
        audit(bg, "SESSION_REVOKED", "warning", jti=body.jti, reason=body.reason)
        return {"revoked": result.rowcount == 1}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz():
        if db_alive(engine):
            return {"status": "ready"}
        return JSONResponse({"status": "db unavailable"}, status_code=503)

    return app


def app_factory() -> FastAPI:  # точка входа uvicorn --factory
    logging.basicConfig(level=logging.INFO)
    return create_app()
