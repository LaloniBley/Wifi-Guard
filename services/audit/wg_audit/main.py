"""Микросервис мониторинга и аудита.

Принимает события безопасности от остальных микросервисов, сохраняет их
в журнал аудита (таблица WG_AUDIT_EVENTS в Oracle) и ведёт метрики
в формате Prometheus, которые отображаются на дашборде Grafana (глава 4).

API:
  POST /events            — регистрация события;
  GET  /events?limit=&type= — последние события (для расследования инцидентов);
  GET  /metrics           — метрики для Prometheus.
"""
import json
import logging
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response
from prometheus_client import (CONTENT_TYPE_LATEST, CollectorRegistry, Counter,
                               Histogram, generate_latest)
from pydantic import BaseModel, ConfigDict
from sqlalchemy import (Column, DateTime, Float, Identity, Integer, MetaData,
                        String, Table, Text, insert, select)
from sqlalchemy.engine import Engine

from wg_common.db import db_alive, init_schema, make_engine

log = logging.getLogger("wg_audit")

metadata = MetaData()
events = Table(
    "wg_audit_events", metadata,
    Column("id", Integer, Identity(), primary_key=True),
    Column("ts", DateTime, nullable=False, index=True),
    Column("service", String(16), nullable=False),
    Column("event_type", String(32), nullable=False, index=True),
    Column("severity", String(16), nullable=False),
    Column("username", String(64)),
    Column("client_ip", String(45)),
    Column("bssid", String(17)),
    Column("verdict", String(16)),
    Column("score", Float),
    Column("scenario", String(4)),
    Column("payload", Text),
)


class EventIn(BaseModel):
    model_config = ConfigDict(extra="allow")   # прочие поля сохраняются в payload
    ts: str | None = None
    service: str
    event_type: str
    severity: str = "info"
    username: str | None = None
    client_ip: str | None = None
    bssid: str | None = None
    verdict: str | None = None
    score: float | None = None
    scenario: str | None = None
    indicators: list[str] | None = None
    reason: str | None = None
    status: int | None = None
    latency_ms: float | None = None


class Metrics:
    """Метрики безопасности паттерна (имена с префиксом wg_)."""

    def __init__(self):
        self.registry = CollectorRegistry()
        self.verdicts = Counter("wg_verdicts_total", "Вердикты микросервиса безопасности",
                                ["verdict", "mode"], registry=self.registry)
        self.indicators = Counter("wg_indicators_total", "Сработавшие индикаторы подмены",
                                  ["indicator", "scenario"], registry=self.registry)
        self.auth_failures = Counter("wg_auth_failures_total", "Отказы аутентификации",
                                     ["reason"], registry=self.registry)
        self.revocations = Counter("wg_sessions_revoked_total", "Отозванные сессии",
                                   registry=self.registry)
        self.requests = Counter("wg_gateway_requests_total", "Запросы через шлюз",
                                ["status"], registry=self.registry)
        self.risk = Histogram("wg_risk_score", "Оценка риска запросов",
                              buckets=(0.0, 0.2, 0.4, 0.6, 0.8, 1.0), registry=self.registry)
        # границы от 5 мс до 2 с: 2 с — тайм-аут внутренних вызовов шлюза
        self.latency = Histogram("wg_gateway_latency_seconds", "Время обработки запроса шлюзом",
                                 buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0),
                                 registry=self.registry)

    def observe(self, ev: EventIn) -> None:
        extra = ev.model_extra or {}
        if ev.event_type == "SECURITY_VERDICT":
            self.verdicts.labels(ev.verdict, extra.get("mode", "request")).inc()
            if ev.score is not None:
                self.risk.observe(ev.score)
            for ind in ev.indicators or []:
                self.indicators.labels(ind, ev.scenario or "-").inc()
        elif ev.event_type == "AUTH_FAILURE":
            self.auth_failures.labels(ev.reason or "unknown").inc()
        elif ev.event_type == "SESSION_REVOKED":
            self.revocations.inc()
        elif ev.event_type == "REQUEST_COMPLETED":
            self.requests.labels(str(ev.status)).inc()
            if ev.latency_ms is not None:
                self.latency.observe(ev.latency_ms / 1000)


def create_app(engine: Engine | None = None) -> FastAPI:
    engine = engine or make_engine()
    init_schema(engine, metadata)
    metrics = Metrics()
    app = FastAPI(title="WiFi-Guard: мониторинг и аудит")

    @app.post("/events", status_code=202)
    def add_event(ev: EventIn):
        metrics.observe(ev)
        ts = datetime.fromisoformat(ev.ts) if ev.ts else datetime.now(timezone.utc)
        payload = {k: v for k, v in ev.model_dump().items()
                   if k not in events.c and v is not None}
        with engine.begin() as conn:
            conn.execute(insert(events).values(
                ts=ts.replace(tzinfo=None), service=ev.service, event_type=ev.event_type,
                severity=ev.severity, username=ev.username, client_ip=ev.client_ip,
                bssid=ev.bssid, verdict=ev.verdict, score=ev.score, scenario=ev.scenario,
                payload=json.dumps(payload, ensure_ascii=False)))
        if ev.severity in ("warning", "critical"):
            log.warning("SECURITY EVENT %s %s", ev.event_type, payload)
        return {"accepted": True}

    @app.get("/events")
    def list_events(limit: int = 50, type: str | None = None):  # noqa: A002
        query = select(events).order_by(events.c.id.desc()).limit(min(limit, 500))
        if type:
            query = query.where(events.c.event_type == type)
        with engine.connect() as conn:
            rows = conn.execute(query).mappings().all()
        return [{**dict(r), "ts": r["ts"].isoformat(),
                 "payload": json.loads(r["payload"] or "{}")} for r in rows]

    @app.get("/metrics")
    def prometheus_metrics():
        return Response(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST)

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
