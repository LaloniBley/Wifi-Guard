"""Выпуск и проверка сессионных токенов, привязанных к контексту подключения.

Токен — JWT (RFC 7519), подписанный HMAC-SHA256. Помимо стандартных полей
он содержит:
  cnf.x5t#S256 — отпечаток клиентского TLS-сертификата устройства
                 (привязка к TLS-сессии по RFC 8705);
  ctx          — сетевой контекст на момент входа: BSSID точки доступа
                 и число транзитных узлов (hops) до сервера.
"""
import hmac
import time
import uuid

import jwt

ALGORITHM = "HS256"


class TokenError(Exception):
    """Причина отказа передаётся в аудит как reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def issue_token(secret: str, username: str, role: str, cert_fp: str,
                bssid: str | None, hops: int | None, ttl_seconds: int) -> tuple[str, dict]:
    now = int(time.time())
    claims = {
        "iss": "wifi-guard-auth",
        "sub": username,
        "role": role,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl_seconds,
        "cnf": {"x5t#S256": cert_fp},
        "ctx": {"bssid": bssid, "hops": hops},
    }
    return jwt.encode(claims, secret, algorithm=ALGORITHM), claims


def check_token(secret: str, token: str, presented_cert_fp: str | None) -> dict:
    """Проверяет подпись, срок действия и привязку токена к сертификату.

    Возвращает полезную нагрузку токена или возбуждает TokenError.
    Проверка отзыва (по jti) выполняется в main.py по таблице сессий.
    """
    try:
        claims = jwt.decode(token, secret, algorithms=[ALGORITHM],
                            options={"require": ["exp", "iat", "jti", "sub"]},
                            issuer="wifi-guard-auth")
    except jwt.ExpiredSignatureError:
        raise TokenError("token_expired")
    except jwt.InvalidTokenError:
        raise TokenError("token_invalid")

    bound_fp = (claims.get("cnf") or {}).get("x5t#S256")
    if not presented_cert_fp or not bound_fp:
        raise TokenError("no_client_certificate")
    # сравнение за постоянное время исключает атаку по времени отклика
    if not hmac.compare_digest(bound_fp, presented_cert_fp):
        raise TokenError("binding_mismatch")
    return claims
