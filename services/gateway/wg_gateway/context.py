"""Извлечение контекста подключения клиента из HTTP-запроса.

Заголовки X-Client-* выставляет TLS-терминатор NGINX, работающий в том же
поде; процесс шлюза слушает только 127.0.0.1, поэтому подделать эти
заголовки извне невозможно. Заголовок X-WG-Telemetry формирует клиентская
часть приложения «Корпоративный портал».
"""
import base64
import hashlib
import json
from urllib.parse import unquote

from wg_common.netutil import normalize_mac

MAX_SCAN_ENTRIES = 64  # больше сетей в одной точке практически не наблюдается


def cert_thumbprint(escaped_pem: str | None) -> str | None:
    """Отпечаток клиентского сертификата SHA-256 в формате x5t#S256 (RFC 8705).

    NGINX передаёт сертификат в PEM-виде, закодированном как URL
    ($ssl_client_escaped_cert). Отпечаток считается от DER-представления:
    base64-тело между строками BEGIN/END декодируется, хешируется SHA-256
    и кодируется base64url без выравнивания '='.
    """
    if not escaped_pem:
        return None
    pem = unquote(escaped_pem)
    lines = [ln.strip() for ln in pem.strip().splitlines()]
    if not lines or "BEGIN CERTIFICATE" not in lines[0]:
        return None
    body = "".join(ln for ln in lines if ln and "CERTIFICATE" not in ln)
    try:
        der = base64.b64decode(body, validate=True)
    except ValueError:
        return None
    digest = hashlib.sha256(der).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def parse_telemetry(header: str | None) -> dict:
    """Декодирует телеметрию клиента: base64url(JSON).

    Ожидаемая структура: {"ssid": str, "bssid": str, "pmf": bool,
    "scan": [{"ssid", "bssid", "channel", "security"}, ...]}.
    При ошибке возвращается пустая телеметрия — это не ошибка запроса,
    а признак, который микросервис безопасности оценит как отсутствие
    подтверждённой ТД (принцип «запрещено всё, что не подтверждено»).
    """
    if not header:
        return {"ssid": None, "bssid": None, "pmf": None, "scan": []}
    try:
        padded = header + "=" * (-len(header) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):
        return {"ssid": None, "bssid": None, "pmf": None, "scan": []}
    scan = data.get("scan") if isinstance(data.get("scan"), list) else []
    return {
        "ssid": str(data["ssid"])[:32] if data.get("ssid") else None,
        "bssid": normalize_mac(data.get("bssid")),
        "pmf": data.get("pmf") if isinstance(data.get("pmf"), bool) else None,
        "scan": [n for n in scan[:MAX_SCAN_ENTRIES] if isinstance(n, dict)],
    }


def bearer_token(authorization: str | None) -> str | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    return authorization[7:].strip() or None
