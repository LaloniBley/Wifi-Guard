"""Микросервис безопасности — ядро паттерна.

POST /evaluate — принимает атрибуты подключения от шлюза, запрашивает
эталонные данные у микросервиса справочных данных, применяет правила
(rules.assess) и возвращает вердикт. При вердикте BLOCK для запроса
с токеном сессия отзывается в микросервисе аутентификации.
"""
import logging
import time

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

from wg_common.audit import emit_background, make_event
from wg_common.netutil import normalize_mac
from wg_common.settings import env, env_float, env_int

from .rules import Config, assess

log = logging.getLogger("wg_security")
SERVICE = "security"


class Telemetry(BaseModel):
    ssid: str | None = None
    bssid: str | None = None
    pmf: bool | None = None
    scan: list[dict] = []


class EvaluateIn(BaseModel):
    mode: str = "request"          # login | request
    username: str | None = None
    jti: str | None = None
    client_ip: str | None = None
    hops: int | None = None
    telemetry: Telemetry = Telemetry()


class RegistryCache:
    """Кэш ответов реестра на 30 с: реестр ТД меняется редко (онбординг),
    а обращение к нему происходит на каждый запрос пользователя."""

    def __init__(self, http: httpx.AsyncClient, base_url: str, ttl: int):
        self.http, self.base_url, self.ttl = http, base_url, ttl
        self._data: dict[str, tuple[float, object]] = {}

    async def _get(self, key: str, path: str, params: dict | None = None):
        hit = self._data.get(key)
        if hit and time.monotonic() - hit[0] < self.ttl:
            return hit[1]
        resp = await self.http.get(f"{self.base_url}{path}", params=params, timeout=2.0)
        if resp.status_code == 404:
            value = None
        else:
            resp.raise_for_status()
            value = resp.json()
        self._data[key] = (time.monotonic(), value)
        return value

    async def ap(self, bssid: str | None):
        if not bssid:
            return None
        return await self._get(f"ap:{bssid}", f"/aps/{bssid}")

    async def aps_by_ssid(self, ssid: str | None):
        if not ssid:
            return []
        return await self._get(f"ssid:{ssid}", "/aps", {"ssid": ssid}) or []


def create_app(http: httpx.AsyncClient | None = None) -> FastAPI:
    http = http or httpx.AsyncClient()
    registry = RegistryCache(http, env("REGISTRY_URL", "http://registry:8003"),
                             env_int("REGISTRY_CACHE_SECONDS", 30))
    auth_url = env("AUTH_URL", "http://auth:8001")
    cfg = Config(
        suspicious_threshold=env_float("SUSPICIOUS_THRESHOLD", 0.4),
        block_threshold=env_float("BLOCK_THRESHOLD", 0.8),
        hops_tolerance=env_int("HOPS_TOLERANCE", 0),
    )
    app = FastAPI(title="WiFi-Guard: микросервис безопасности")

    @app.post("/evaluate")
    async def evaluate(body: EvaluateIn):
        tel = body.telemetry.model_dump()
        tel["bssid"] = normalize_mac(tel.get("bssid"))
        ap = await registry.ap(tel["bssid"])
        ssid_aps = await registry.aps_by_ssid(tel.get("ssid"))
        result = assess(tel, body.hops, ap, ssid_aps, cfg)

        revoked = False
        if result.verdict == "BLOCK" and body.jti:
            resp = await http.post(f"{auth_url}/internal/revoke",
                                   json={"jti": body.jti, "reason": "security_block"},
                                   timeout=2.0)
            revoked = resp.status_code == 200 and resp.json().get("revoked", False)

        severity = {"ALLOW": "info", "SUSPICIOUS": "warning", "BLOCK": "critical"}[result.verdict]
        emit_background(http, make_event(
            SERVICE, "SECURITY_VERDICT", severity, verdict=result.verdict,
            score=result.score, indicators=result.indicators, scenario=result.scenario,
            username=body.username, jti=body.jti, client_ip=body.client_ip,
            bssid=tel["bssid"], mode=body.mode, details=result.details))
        return {"verdict": result.verdict, "score": result.score,
                "indicators": result.indicators, "scenario": result.scenario,
                "session_revoked": revoked}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app


def app_factory() -> FastAPI:
    logging.basicConfig(level=logging.INFO)
    return create_app()
