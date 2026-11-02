"""Отправка событий в микросервис мониторинга и аудита.

Отправка выполняется «по принципу fire-and-forget»: недоступность аудита
не должна блокировать обработку запроса пользователя, поэтому ошибки
только записываются в журнал контейнера (его собирает kubelet).
"""
import asyncio
import logging
from datetime import datetime, timezone

import httpx

from .settings import env

log = logging.getLogger(__name__)

AUDIT_TIMEOUT = 1.0  # с; событие не должно задерживать ответ пользователю


def make_event(service: str, event_type: str, severity: str = "info", **fields) -> dict:
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "event_type": event_type,
        "severity": severity,
    }
    event.update({k: v for k, v in fields.items() if v is not None})
    return event


_background: set[asyncio.Task] = set()


def emit_background(client: httpx.AsyncClient, event: dict) -> None:
    """Отправляет событие в фоне, не задерживая ответ клиенту."""
    task = asyncio.get_running_loop().create_task(emit_async(client, event))
    _background.add(task)              # ссылка нужна, чтобы задачу не удалил GC
    task.add_done_callback(_background.discard)


async def emit_async(client: httpx.AsyncClient, event: dict) -> None:
    url = env("AUDIT_URL", "http://audit:8004")
    try:
        await client.post(f"{url}/events", json=event, timeout=AUDIT_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        log.error("audit unavailable: %s; event=%s", exc, event)


def emit_sync(client: httpx.Client, event: dict) -> None:
    url = env("AUDIT_URL", "http://audit:8004")
    try:
        client.post(f"{url}/events", json=event, timeout=AUDIT_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        log.error("audit unavailable: %s; event=%s", exc, event)
