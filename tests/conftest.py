"""Общая подготовка автотестов.

Все микросервисы поднимаются в одном процессе: HTTP-вызовы между ними
маршрутизируются по имени хоста (auth, security, registry, audit, portal,
127.0.0.1 — TTL-зонд) напрямую в ASGI-приложения, без сети и Docker.
Вместо Oracle используется SQLite в памяти.
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
for p in ["common", "client", "services/gateway", "services/auth", "services/security",
          "services/registry", "services/audit", "services/portal", "services/ttl-probe"]:
    sys.path.insert(0, str(ROOT / p))

os.environ.update({
    "JWT_SECRET": "test-secret-0123456789abcdef0123456789abcdef",
    "PBKDF2_ITERATIONS": "1000",          # ускорение тестов (в кластере 600 000)
    "REGISTRY_ADMIN_KEY": "test-admin-key",
    "SEED_USERS": "ivanov:Ivanov#2026:user;admin:Admin#2026:admin",
    "SEED_APS": '[{"bssid": "A0-B1-C2-D3-E4-01", "ssid": "CORP-WIFI", "channel": 36,'
                ' "security": "WPA3-SAE", "pmf_required": true, "ref_hops": 2}]',
    "REGISTRY_CACHE_SECONDS": "0",
})

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from wg_common.db import make_engine  # noqa: E402


def make_cert_pem(cn: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class Router(httpx.AsyncBaseTransport):
    """Маршрутизация запросов httpx к ASGI-приложениям по имени хоста."""

    def __init__(self, apps: dict):
        self.apps = {host: httpx.ASGITransport(app=app) for host, app in apps.items()}
        self.down: set[str] = set()

    async def handle_async_request(self, request):
        host = request.url.host
        if host in self.down or host not in self.apps:
            raise httpx.ConnectError(f"{host} unreachable", request=request)
        return await self.apps[host].handle_async_request(request)


class Cluster:
    def __init__(self):
        from wg_audit.main import create_app as audit_app
        from wg_auth.main import create_app as auth_app
        from wg_gateway.main import create_app as gateway_app
        from wg_portal.main import create_app as portal_app
        from wg_registry.main import create_app as registry_app
        from wg_security.main import create_app as security_app

        self.hops = 2
        probe = FastAPI()

        @probe.get("/hops")
        def hops(ip: str):
            return {"ip": ip, "ttl": 64 - self.hops, "initial_ttl": 64, "hops": self.hops}

        self.audit = audit_app(make_engine("sqlite+pysqlite:///:memory:"))
        self.audit_client = TestClient(self.audit)
        self.router = Router({})
        http = httpx.AsyncClient(transport=self.router)
        apps = {
            "audit": self.audit,
            "auth": auth_app(make_engine("sqlite+pysqlite:///:memory:"), http=self.audit_client),
            "registry": registry_app(make_engine("sqlite+pysqlite:///:memory:")),
            "security": security_app(http=http),
            "portal": portal_app(),
            "127.0.0.1": probe,
        }
        self.router.apps = {h: httpx.ASGITransport(app=a) for h, a in apps.items()}
        self.gateway = TestClient(gateway_app(http=http))
        self.user_cert = make_cert_pem("user1")
        self.attacker_cert = make_cert_pem("attacker")

    def headers(self, telemetry: str, cert: str | None = None, token: str | None = None):
        h = {"X-Client-Verify": "SUCCESS", "X-Client-Cert": quote(cert or self.user_cert),
             "X-Real-IP": "10.10.0.15", "X-WG-Telemetry": telemetry}
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    def login(self, telemetry: str, user="ivanov", password="Ivanov#2026", cert=None):
        return self.gateway.post("/api/login", json={"username": user, "password": password},
                                 headers=self.headers(telemetry, cert))


@pytest.fixture
def cluster():
    return Cluster()
