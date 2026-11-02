"""Микросервис справочных данных и реестров.

Хранит реестр доверенных точек доступа (эталонные данные для сверки):
BSSID, SSID, канал, режим защиты, требование PMF (802.11w) и эталонное
число транзитных узлов (hops) от ТД до сервера.

API:
  GET    /aps/{bssid}      — запись о ТД (для микросервиса безопасности);
  GET    /aps?ssid=...     — все доверенные ТД сети с данным SSID;
  POST   /aps              — онбординг новой ТД (только с ключом администратора);
  DELETE /aps/{bssid}      — вывод ТД из реестра (только с ключом администратора).
"""
import hmac
import json
import logging
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import (Boolean, Column, DateTime, Integer, MetaData, String,
                        Table, insert, select, update)
from sqlalchemy.engine import Engine

from wg_common.db import db_alive, init_schema, make_engine
from wg_common.netutil import normalize_mac
from wg_common.settings import env

log = logging.getLogger("wg_registry")

metadata = MetaData()
trusted_aps = Table(
    "wg_trusted_aps", metadata,
    Column("bssid", String(17), primary_key=True),
    Column("ssid", String(32), nullable=False, index=True),
    Column("channel", Integer, nullable=False),
    Column("security", String(16), nullable=False),
    Column("pmf_required", Boolean, nullable=False, default=True),
    Column("ref_hops", Integer),
    Column("location", String(128)),
    Column("active", Boolean, nullable=False, default=True),
    Column("created_at", DateTime, nullable=False),
)


class ApIn(BaseModel):
    bssid: str
    ssid: str = Field(min_length=1, max_length=32)  # SSID ограничен 32 байтами (IEEE 802.11)
    channel: int = Field(ge=1, le=233)               # номера каналов 2,4/5/6 ГГц
    security: str = "WPA3-SAE"
    pmf_required: bool = True
    ref_hops: int | None = Field(default=None, ge=0, le=64)
    location: str | None = None


def row_to_dict(row) -> dict:
    return {"bssid": row.bssid, "ssid": row.ssid, "channel": row.channel,
            "security": row.security, "pmf_required": bool(row.pmf_required),
            "ref_hops": row.ref_hops, "location": row.location}


def upsert_ap(engine: Engine, ap: ApIn) -> dict:
    """Добавляет ТД в реестр или обновляет её эталонные параметры."""
    bssid = normalize_mac(ap.bssid)
    if bssid is None:
        raise HTTPException(422, "bssid is not a MAC address")
    values = ap.model_dump()
    values["bssid"] = bssid
    with engine.begin() as conn:
        exists = conn.execute(select(trusted_aps.c.bssid)
                              .where(trusted_aps.c.bssid == bssid)).first()
        if exists:
            conn.execute(update(trusted_aps).where(trusted_aps.c.bssid == bssid)
                         .values(active=True, **{k: v for k, v in values.items() if k != "bssid"}))
        else:
            conn.execute(insert(trusted_aps).values(
                active=True, created_at=datetime.now(timezone.utc).replace(tzinfo=None), **values))
    return values


def create_app(engine: Engine | None = None) -> FastAPI:
    engine = engine or make_engine()
    admin_key = env("REGISTRY_ADMIN_KEY", required=True)
    init_schema(engine, metadata)
    # начальный реестр только добавляется: калибровка эталонов при перезапуске не теряется
    for item in json.loads(env("SEED_APS", "[]")):
        with engine.connect() as conn:
            exists = conn.execute(select(trusted_aps.c.bssid).where(
                trusted_aps.c.bssid == normalize_mac(item["bssid"]))).first()
        if not exists:
            upsert_ap(engine, ApIn(**item))

    app = FastAPI(title="WiFi-Guard: справочные данные и реестры")

    def require_admin(key: str | None):
        if not key or not hmac.compare_digest(key, admin_key):
            raise HTTPException(403, "admin key required")

    @app.get("/aps/{bssid}")
    def get_ap(bssid: str):
        norm = normalize_mac(bssid)
        with engine.connect() as conn:
            row = conn.execute(select(trusted_aps).where(
                trusted_aps.c.bssid == norm, trusted_aps.c.active)).first()
        if row is None:
            return JSONResponse({"detail": "not trusted"}, status_code=404)
        return row_to_dict(row)

    @app.get("/aps")
    def list_aps(ssid: str | None = None):
        query = select(trusted_aps).where(trusted_aps.c.active)
        if ssid:
            query = query.where(trusted_aps.c.ssid == ssid)
        with engine.connect() as conn:
            return [row_to_dict(r) for r in conn.execute(query)]

    @app.post("/aps", status_code=201)
    def add_ap(ap: ApIn, x_admin_key: str | None = Header(default=None)):
        require_admin(x_admin_key)
        return upsert_ap(engine, ap)

    @app.delete("/aps/{bssid}")
    def remove_ap(bssid: str, x_admin_key: str | None = Header(default=None)):
        require_admin(x_admin_key)
        with engine.begin() as conn:
            res = conn.execute(update(trusted_aps)
                               .where(trusted_aps.c.bssid == normalize_mac(bssid))
                               .values(active=False))
        return {"removed": res.rowcount == 1}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz():
        if db_alive(engine):
            return {"status": "ready"}
        return JSONResponse({"status": "db unavailable"}, status_code=503)

    return app


def app_factory() -> FastAPI:
    logging.basicConfig(level=logging.INFO)
    return create_app()
