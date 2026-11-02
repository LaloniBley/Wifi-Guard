"""Шлюз доступа (API Gateway) — единственная точка входа в приложение.

Конвейер обработки запроса к порталу (рис. 9 главы 3):
  1) клиентский сертификат проверен NGINX (mTLS), вычисляется его отпечаток;
  2) извлекается сессионный токен и телеметрия Wi-Fi;
  3) TTL-зонд сообщает число транзитных узлов до клиента;
  4) микросервис аутентификации проверяет токен и его привязку  -> 401;
  5) микросервис безопасности выносит вердикт                   -> 403;
  6) верифицированный запрос проксируется в «Корпоративный портал».
Любая недоступность зависимостей приводит к отказу (503): шлюз работает
по принципу «закрыт при сбое» (fail-closed).
"""
import logging
import time

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from wg_common.audit import emit_background, make_event
from wg_common.settings import env

from .context import bearer_token, cert_thumbprint, parse_telemetry

log = logging.getLogger("wg_gateway")
SERVICE = "gateway"
TIMEOUT = 2.0  # с; внутрикластерные вызовы занимают миллисекунды


class LoginIn(BaseModel):
    username: str
    password: str


class ApOnboardIn(BaseModel):
    bssid: str
    ssid: str
    channel: int
    security: str = "WPA3-SAE"
    pmf_required: bool = True
    ref_hops: int | None = None
    calibrate: bool = False      # взять эталон hops из текущего подключения
    location: str | None = None


class Denied(Exception):
    def __init__(self, status: int, detail: str, extra: dict | None = None):
        self.status, self.detail, self.extra = status, detail, extra or {}


def create_app(http: httpx.AsyncClient | None = None) -> FastAPI:
    http = http or httpx.AsyncClient()
    urls = {
        "auth": env("AUTH_URL", "http://auth:8001"),
        "security": env("SECURITY_URL", "http://security:8002"),
        "registry": env("REGISTRY_URL", "http://registry:8003"),
        "portal": env("PORTAL_URL", "http://portal:8000"),
        "probe": env("TTL_PROBE_URL", "http://127.0.0.1:9100"),
    }
    registry_key = env("REGISTRY_ADMIN_KEY", "")
    app = FastAPI(title="WiFi-Guard: шлюз доступа")

    @app.exception_handler(Denied)
    async def denied_handler(request: Request, exc: Denied):
        return JSONResponse({"detail": exc.detail, **exc.extra}, status_code=exc.status)

    async def call(method: str, url: str, **kw) -> httpx.Response:
        try:
            return await http.request(method, url, timeout=TIMEOUT, **kw)
        except httpx.HTTPError as err:
            log.error("dependency failure %s: %s", url, err)
            raise Denied(503, "security dependency unavailable")

    async def observed_hops(ip: str | None) -> int | None:
        if not ip:
            return None
        try:
            resp = await http.get(f"{urls['probe']}/hops", params={"ip": ip}, timeout=0.5)
        except httpx.HTTPError:
            return None   # нет данных зонда: индикатор N1 не оценивается
        return resp.json().get("hops") if resp.status_code == 200 else None

    def client_context(request: Request) -> dict:
        if request.headers.get("x-client-verify") != "SUCCESS":
            raise Denied(401, "client certificate required")
        fp = cert_thumbprint(request.headers.get("x-client-cert"))
        if fp is None:
            raise Denied(401, "client certificate unreadable")
        return {"cert_fp": fp, "ip": request.headers.get("x-real-ip"),
                "telemetry": parse_telemetry(request.headers.get("x-wg-telemetry"))}

    async def verify_token(request: Request, ctx: dict) -> dict:
        token = bearer_token(request.headers.get("authorization"))
        if token is None:
            raise Denied(401, "bearer token required")
        resp = await call("POST", f"{urls['auth']}/internal/verify",
                          json={"token": token, "cert_fp": ctx["cert_fp"], "client_ip": ctx["ip"]})
        if resp.status_code == 401:
            raise Denied(401, "token rejected", {"reason": resp.json().get("reason")})
        if resp.status_code != 200:
            raise Denied(503, "auth service error")
        return resp.json()

    async def security_verdict(mode: str, ctx: dict, hops: int | None,
                               user: str | None, jti: str | None) -> dict:
        resp = await call("POST", f"{urls['security']}/evaluate", json={
            "mode": mode, "username": user, "jti": jti, "client_ip": ctx["ip"],
            "hops": hops, "telemetry": ctx["telemetry"]})
        if resp.status_code != 200:
            raise Denied(503, "security service error")
        verdict = resp.json()
        if verdict["verdict"] == "BLOCK":
            raise Denied(403, "access blocked: signs of wireless node spoofing",
                         {"indicators": verdict["indicators"], "scenario": verdict["scenario"]})
        return verdict

    @app.middleware("http")
    async def audit_request(request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        if request.url.path not in ("/healthz",):
            emit_background(http, make_event(
                SERVICE, "REQUEST_COMPLETED", "info", path=request.url.path,
                status=response.status_code, client_ip=request.headers.get("x-real-ip"),
                latency_ms=round((time.perf_counter() - started) * 1000, 2)))
        return response

    @app.post("/api/login")
    async def login(body: LoginIn, request: Request):
        ctx = client_context(request)
        hops = await observed_hops(ctx["ip"])
        await security_verdict("login", ctx, hops, body.username, None)
        resp = await call("POST", f"{urls['auth']}/internal/login", json={
            "username": body.username, "password": body.password,
            "cert_fp": ctx["cert_fp"], "bssid": ctx["telemetry"]["bssid"],
            "hops": hops, "client_ip": ctx["ip"]})
        return JSONResponse(resp.json(), status_code=resp.status_code)

    @app.api_route("/portal/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def portal(path: str, request: Request):
        ctx = client_context(request)
        claims = await verify_token(request, ctx)
        hops = await observed_hops(ctx["ip"])
        verdict = await security_verdict("request", ctx, hops, claims["sub"], claims["jti"])
        upstream = await call(
            request.method, f"{urls['portal']}/portal/{path}",
            params=request.query_params, content=await request.body(),
            headers={"X-WG-User": claims["sub"], "X-WG-Role": claims["role"],
                     "X-WG-Verdict": verdict["verdict"],
                     "Content-Type": request.headers.get("content-type", "application/json")})
        return Response(upstream.content, status_code=upstream.status_code,
                        media_type=upstream.headers.get("content-type"),
                        headers={"X-WG-Verdict": verdict["verdict"]})

    @app.post("/api/admin/aps", status_code=201)
    async def onboard_ap(body: ApOnboardIn, request: Request):
        ctx = client_context(request)
        claims = await verify_token(request, ctx)
        if claims["role"] != "admin":
            raise Denied(403, "admin role required")
        ap = body.model_dump(exclude={"calibrate"})
        if body.calibrate:
            ap["ref_hops"] = await observed_hops(ctx["ip"])
        resp = await call("POST", f"{urls['registry']}/aps", json=ap,
                          headers={"X-Admin-Key": registry_key})
        return JSONResponse(resp.json(), status_code=resp.status_code)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app


def app_factory() -> FastAPI:
    logging.basicConfig(level=logging.INFO)
    return create_app()
