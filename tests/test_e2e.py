"""Сквозные тесты: шлюз + все микросервисы в одном процессе.

Проверяются легитимная работа и сценарии С1 и С2 угрозы УБИ.126.
"""
from client_sim import telemetry_for


def portal(cluster, token, scenario="normal", cert=None):
    return cluster.gateway.get("/portal/profile",
                               headers=cluster.headers(telemetry_for(scenario), cert, token))


def test_legitimate_user_gets_portal(cluster):
    r = cluster.login(telemetry_for("normal"))
    assert r.status_code == 200
    resp = portal(cluster, r.json()["access_token"])
    assert resp.status_code == 200
    assert resp.json()["user"] == "ivanov" and resp.headers["X-WG-Verdict"] == "ALLOW"


def test_wrong_password_rejected(cluster):
    assert cluster.login(telemetry_for("normal"), password="bad").status_code == 401


def test_no_client_certificate_rejected(cluster):
    h = cluster.headers(telemetry_for("normal"))
    h["X-Client-Verify"] = "NONE"
    r = cluster.gateway.post("/api/login", json={"username": "ivanov", "password": "x"}, headers=h)
    assert r.status_code == 401


def test_c1_rogue_ap_blocks_login(cluster):
    r = cluster.login(telemetry_for("rogue-ap"))
    assert r.status_code == 403 and r.json()["scenario"] == "C1"
    assert "BSSID_UNTRUSTED" in r.json()["indicators"]


def test_c1_evil_twin_blocks_and_revokes_session(cluster):
    token = cluster.login(telemetry_for("normal")).json()["access_token"]
    r = portal(cluster, token, "evil-twin")      # клиента «переманили» на двойника
    assert r.status_code == 403
    assert set(r.json()["indicators"]) == {"PMF_NOT_NEGOTIATED", "TWIN_IN_AIR"}
    # сессия прекращена: тот же токен больше не принимается даже от легитимной ТД
    r2 = portal(cluster, token, "normal")
    assert r2.status_code == 401 and r2.json()["reason"] == "session_revoked"


def test_c1_full_relay_is_suspicious_but_allowed(cluster):
    token = cluster.login(telemetry_for("normal")).json()["access_token"]
    r = portal(cluster, token, "relay")
    assert r.status_code == 200 and r.headers["X-WG-Verdict"] == "SUSPICIOUS"


def test_c1_relay_with_extra_hop_blocked(cluster):
    token = cluster.login(telemetry_for("normal")).json()["access_token"]
    cluster.hops = 3                              # ретранслятор нарушителя добавил узел
    assert portal(cluster, token, "relay").status_code == 403


def test_c2_stolen_token_rejected(cluster):
    token = cluster.login(telemetry_for("normal")).json()["access_token"]
    r = portal(cluster, token, cert=cluster.attacker_cert)
    assert r.status_code == 401 and r.json()["reason"] == "binding_mismatch"


def test_admin_onboarding_with_calibration(cluster):
    token = cluster.login(telemetry_for("normal"), user="admin",
                          password="Admin#2026").json()["access_token"]
    body = {"bssid": "a0:b1:c2:d3:e4:02", "ssid": "CORP-WIFI", "channel": 40,
            "calibrate": True}
    r = cluster.gateway.post("/api/admin/aps", json=body,
                             headers=cluster.headers(telemetry_for("normal"), token=token))
    assert r.status_code == 201 and r.json()["ref_hops"] == 2


def test_user_cannot_onboard_ap(cluster):
    token = cluster.login(telemetry_for("normal")).json()["access_token"]
    r = cluster.gateway.post("/api/admin/aps",
                             json={"bssid": "a0:b1:c2:d3:e4:09", "ssid": "X", "channel": 1},
                             headers=cluster.headers(telemetry_for("normal"), token=token))
    assert r.status_code == 403


def test_fail_closed_when_security_down(cluster):
    token = cluster.login(telemetry_for("normal")).json()["access_token"]
    cluster.router.down.add("security")
    assert portal(cluster, token).status_code == 503


def test_audit_metrics_and_journal(cluster):
    token = cluster.login(telemetry_for("normal")).json()["access_token"]
    portal(cluster, token, "evil-twin")
    metrics = cluster.audit_client.get("/metrics").text
    assert 'wg_verdicts_total{mode="request",verdict="BLOCK"} 1.0' in metrics
    assert "wg_sessions_revoked_total 1.0" in metrics
    events = cluster.audit_client.get("/events", params={"type": "SECURITY_VERDICT"}).json()
    assert events[0]["verdict"] == "BLOCK" and events[0]["scenario"] == "C1"


def test_portal_rejects_requests_bypassing_gateway(cluster):
    from fastapi.testclient import TestClient
    from wg_portal.main import create_app
    assert TestClient(create_app()).get("/portal/profile").status_code == 403


def test_seed_does_not_overwrite_calibration(cluster):
    """Перезапуск реестра не должен стирать откалиброванный эталон hops."""
    from wg_common.db import make_engine
    from wg_registry.main import create_app
    from fastapi.testclient import TestClient
    engine = make_engine("sqlite+pysqlite:///:memory:")
    c1 = TestClient(create_app(engine))
    c1.post("/aps", json={"bssid": "a0:b1:c2:d3:e4:01", "ssid": "CORP-WIFI", "channel": 36,
                          "ref_hops": 5}, headers={"X-Admin-Key": "test-admin-key"})
    c2 = TestClient(create_app(engine))          # «перезапуск» с тем же SEED_APS
    assert c2.get("/aps/a0:b1:c2:d3:e4:01").json()["ref_hops"] == 5
