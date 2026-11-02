"""Симулятор клиентской части «Корпоративного портала».

Формирует телеметрию беспроводного подключения (SSID, BSSID, статус PMF,
список видимых сетей) и выполняет запросы к шлюзу по mTLS. Позволяет
воспроизвести легитимную работу и сценарии угрозы УБИ.126:

  normal      — легитимный клиент у доверенной ТД;
  rogue-ap    — подключение через ТД, отсутствующую в реестре (C1);
  evil-twin   — «злой двойник» с клонированным BSSID без PMF (C1);
  relay       — двойник с полной ретрансляцией: PMF «есть», но в эфире
                виден клон на другом канале (C1, вердикт SUSPICIOUS/BLOCK);
  stolen-token— токен легитимного пользователя предъявлен с устройства
                нарушителя (другой сертификат) (C2);
  calibrate   — вход администратора и калибровка эталона hops для ТД
                CORP-WIFI (выполняется один раз после развертывания).

Пример:
  python client_sim.py --base https://192.168.49.2:30443 --scenario normal \
      --ca ../certs/ca.crt --cert ../certs/user1.crt --key ../certs/user1.key
"""
import argparse
import base64
import json
import ssl
import sys

import httpx

LEGIT_AP = {"ssid": "CORP-WIFI", "bssid": "a0:b1:c2:d3:e4:01", "channel": 36,
            "security": "WPA3-SAE"}


def tls_context(ca: str, cert: tuple[str, str]) -> ssl.SSLContext:
    """TLS-контекст клиента: доверенный УЦ + сертификат устройства для mTLS.

    Контекст собирается явно: в httpx 0.28 при verify=<путь> параметр cert
    игнорируется, и сертификат устройства не отправляется серверу.
    Клиенты создаются с trust_env=False: системный прокси (VPN-клиенты в Windows)
    не должен перехватывать обращения к шлюзу в локальной сети.
    """
    ctx = ssl.create_default_context(cafile=ca)
    # Python 3.13+ по умолчанию включает строгую проверку X.509 (VERIFY_X509_STRICT),
    # которую не проходят сертификаты, выпущенные ранними версиями gen-certs.sh
    # (без расширения keyUsage у УЦ). Цепочка, срок и имя сервера проверяются как обычно.
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    ctx.load_cert_chain(*cert)
    return ctx


def encode_telemetry(ssid: str, bssid: str, pmf: bool, scan: list[dict]) -> str:
    """Телеметрия передаётся в заголовке X-WG-Telemetry как base64url(JSON)."""
    raw = json.dumps({"ssid": ssid, "bssid": bssid, "pmf": pmf, "scan": scan},
                     ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def telemetry_for(scenario: str) -> str:
    legit_scan = [dict(LEGIT_AP)]
    if scenario == "rogue-ap":
        return encode_telemetry("CORP-WIFI", "de:ad:be:ef:00:01", False,
                                legit_scan + [{"ssid": "CORP-WIFI", "bssid": "de:ad:be:ef:00:01",
                                               "channel": 6, "security": "OPEN"}])
    if scenario == "evil-twin":
        # BSSID и SSID скопированы, но двойник не поддерживает PMF и работает на канале 6
        return encode_telemetry("CORP-WIFI", LEGIT_AP["bssid"], False,
                                legit_scan + [{**LEGIT_AP, "channel": 6, "security": "WPA2-PSK"}])
    if scenario == "relay":
        return encode_telemetry("CORP-WIFI", LEGIT_AP["bssid"], True,
                                legit_scan + [{**LEGIT_AP, "channel": 6}])
    return encode_telemetry("CORP-WIFI", LEGIT_AP["bssid"], True, legit_scan)


def calibrate(base: str, ca: str, cert: tuple[str, str], user: str, password: str) -> int:
    """Онбординг/калибровка доверенной ТД: эталон hops берётся из текущего маршрута."""
    headers = {"X-WG-Telemetry": telemetry_for("normal")}
    with httpx.Client(base_url=base, verify=tls_context(ca, cert), timeout=10, trust_env=False) as client:
        r = client.post("/api/login", json={"username": user, "password": password}, headers=headers)
        print(f"POST /api/login -> {r.status_code}")
        if r.status_code != 200:
            return r.status_code
        headers["Authorization"] = "Bearer " + r.json()["access_token"]
        body = {**LEGIT_AP, "pmf_required": True, "calibrate": True, "location": "Корпус 1, этаж 3"}
        r = client.post("/api/admin/aps", json=body, headers=headers)
        print(f"POST /api/admin/aps -> {r.status_code} {r.text[:200]}")
        return r.status_code


def run(base: str, scenario: str, ca: str, cert: tuple[str, str],
        attacker_cert: tuple[str, str] | None, user: str, password: str) -> int:
    headers = {"X-WG-Telemetry": telemetry_for(scenario)}
    with httpx.Client(base_url=base, verify=tls_context(ca, cert), timeout=10, trust_env=False) as client:
        login_headers = {"X-WG-Telemetry": telemetry_for("normal")} \
            if scenario == "stolen-token" else headers
        r = client.post("/api/login", json={"username": user, "password": password},
                        headers=login_headers)
        print(f"POST /api/login -> {r.status_code} {r.text[:200]}")
        if r.status_code != 200:
            return r.status_code
        token = r.json()["access_token"]

    if scenario == "stolen-token":
        if not attacker_cert:
            sys.exit("для stolen-token укажите --attacker-cert и --attacker-key")
        cert = attacker_cert
    headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(base_url=base, verify=tls_context(ca, cert), timeout=10, trust_env=False) as client:
        r = client.get("/portal/profile", headers=headers)
        print(f"GET /portal/profile -> {r.status_code} {r.text[:200]}")
        return r.status_code


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default="https://192.168.49.2:30443")
    p.add_argument("--scenario", default="normal",
                   choices=["normal", "rogue-ap", "evil-twin", "relay", "stolen-token",
                            "calibrate"])
    p.add_argument("--ca", default="certs/ca.crt")
    p.add_argument("--cert", default="certs/user1.crt")
    p.add_argument("--key", default="certs/user1.key")
    p.add_argument("--attacker-cert", default="certs/attacker.crt")
    p.add_argument("--attacker-key", default="certs/attacker.key")
    p.add_argument("--user", default="ivanov")
    p.add_argument("--password", default="Ivanov#2026")
    p.add_argument("--admin-cert", default="certs/admin1.crt")
    p.add_argument("--admin-key", default="certs/admin1.key")
    p.add_argument("--admin-user", default="admin")
    p.add_argument("--admin-password", default="Admin#2026")
    a = p.parse_args()
    if a.scenario == "calibrate":
        calibrate(a.base, a.ca, (a.admin_cert, a.admin_key), a.admin_user, a.admin_password)
        return
    run(a.base, a.scenario, a.ca, (a.cert, a.key), (a.attacker_cert, a.attacker_key),
        a.user, a.password)


if __name__ == "__main__":
    main()
