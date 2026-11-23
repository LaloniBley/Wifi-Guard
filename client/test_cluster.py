"""Системные тесты паттерна на развёрнутом кластере (глава 4).

Запускаются с ВМ «пользователь» по сети, через опубликованный шлюз — так же,
как работает настоящий клиент: mTLS, телеметрия Wi-Fi, сессионный токен.
Без переменной WG_BASE тесты пропускаются (в CI кластера нет).

  export WG_BASE=https://192.168.56.10:8443
  python3 -m pytest -v test_cluster.py

Сертификаты берутся из каталога WG_CERTS (по умолчанию ./certs): ca.crt,
user1.* (пользователь), admin1.* (администратор), attacker.* (нарушитель).
Перед запуском эталон маршрута должен быть откалиброван с этой ВМ
(client_sim.py --scenario calibrate), а ВМ подключена к легитимной ТД.
"""
import os
import time
from pathlib import Path

import httpx
import pytest

from client_sim import telemetry_for, tls_context
from experiment import forge, no_cert_context

BASE = os.getenv("WG_BASE")
CERTS = Path(os.getenv("WG_CERTS", "certs"))
USER = {"username": "ivanov", "password": "Ivanov#2026"}

pytestmark = pytest.mark.skipif(not BASE, reason="задайте WG_BASE — адрес шлюза на стенде")


def client(device: str | None = "user1") -> httpx.Client:
    ctx = (tls_context(str(CERTS / "ca.crt"), (str(CERTS / f"{device}.crt"), str(CERTS / f"{device}.key")))
           if device else no_cert_context(str(CERTS / "ca.crt")))
    return httpx.Client(base_url=BASE, verify=ctx, timeout=10, trust_env=False)


def login(c: httpx.Client, scenario: str = "normal", creds: dict = USER) -> httpx.Response:
    return c.post("/api/login", json=creds, headers={"X-WG-Telemetry": telemetry_for(scenario)})


def portal(c: httpx.Client, token: str, scenario: str = "normal") -> httpx.Response:
    return c.get("/portal/profile", headers={"X-WG-Telemetry": telemetry_for(scenario),
                                             "Authorization": f"Bearer {token}"})


@pytest.fixture(autouse=True)
def pause():
    # не превышать ограничение NGINX (10 запросов/с с одного адреса)
    yield
    time.sleep(0.5)


@pytest.fixture
def user():
    with client("user1") as c:
        yield c


@pytest.fixture
def token(user):
    r = login(user)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


# ---------- легитимная работа ----------

def test_legitimate_user_gets_access(user, token):
    r = portal(user, token)
    assert r.status_code == 200
    assert r.headers["x-wg-verdict"] == "ALLOW"
    assert r.json()["user"] == "ivanov"


def test_wrong_password_rejected(user):
    r = login(user, creds={"username": "ivanov", "password": "wrong"})
    assert r.status_code == 401


def test_user_cannot_change_ap_registry(user, token):
    r = user.post("/api/admin/aps", json={"bssid": "de:ad:be:ef:00:01", "ssid": "CORP-WIFI", "channel": 6},
                  headers={"X-WG-Telemetry": telemetry_for("normal"), "Authorization": f"Bearer {token}"})
    assert r.status_code == 403


# ---------- сценарий С1: подмена точки доступа ----------

def test_rogue_ap_blocked_at_login(user):
    r = login(user, "rogue-ap")
    assert r.status_code == 403
    assert "BSSID_UNTRUSTED" in r.json()["indicators"]


def test_evil_twin_without_pmf_blocked(user):
    r = login(user, "evil-twin")
    assert r.status_code == 403
    assert {"PMF_NOT_NEGOTIATED", "TWIN_IN_AIR"} <= set(r.json()["indicators"])


def test_missing_telemetry_blocked(user):
    r = user.post("/api/login", json=USER)
    assert r.status_code == 403
    assert "BSSID_UNTRUSTED" in r.json()["indicators"]


def test_twin_in_air_marked_suspicious(user, token):
    r = portal(user, token, "relay")
    assert r.status_code == 200
    assert r.headers["x-wg-verdict"] == "SUSPICIOUS"


def test_block_revokes_session(user, token):
    # клиента «перетянули» на двойника без PMF посреди сессии
    assert portal(user, token, "evil-twin").status_code == 403
    # сессия отозвана: тот же токен больше не принимается даже с нормальной телеметрией
    r = portal(user, token, "normal")
    assert r.status_code == 401
    assert r.json()["reason"] == "session_revoked"


# ---------- сценарий С2: подмена клиента ----------

def test_stolen_token_from_other_device_rejected(token):
    with client("attacker") as attacker:
        r = portal(attacker, token)
    assert r.status_code == 401
    assert r.json()["reason"] == "binding_mismatch"


def test_stolen_token_without_certificate_rejected(token):
    with client(None) as anonymous:
        r = portal(anonymous, token)
    assert r.status_code == 401


def test_forged_token_rejected(user, token):
    r = portal(user, forge(token))
    assert r.status_code == 401
    assert r.json()["reason"] == "token_invalid"


def test_request_without_token_rejected(user):
    r = user.get("/portal/profile", headers={"X-WG-Telemetry": telemetry_for("normal")})
    assert r.status_code == 401
