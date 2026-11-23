"""Серийные испытания паттерна на стенде (глава 4).

Скрипт многократно воспроизводит один сценарий — легитимную работу или атаку —
и считает, сколько раз доступ был разрешён, помечен как подозрительный или
заблокирован. Каждая попытка записывается в CSV, в конце печатается сводка
с долями исходов и временем ответа.

Сценарии (--scenario):
  normal, rogue-ap, evil-twin, relay — вход и запрос к порталу с телеметрией
                     соответствующего сценария (как в client_sim.py);
  clone            — «идеальный клон»: нарушитель скопировал BSSID, канал и PMF,
                     двойник в эфире не виден; телеметрия как у normal, выдать
                     атаку может только маршрут (запуск через подменную ТД);
  export-token     — вход легитимного пользователя и сохранение токена в файл
                     (имитация перехвата токена нарушителем, сценарий С2);
  stolen-token     — запрос к порталу с перехваченным токеном и сертификатом
                     устройства нарушителя (--cert/--key);
  no-cert          — запрос с перехваченным токеном без сертификата устройства;
  forged-token     — запрос с токеном, в котором нарушитель изменил роль на admin;
  password-guess   — подбор пароля пользователя (заведомо неверные пароли).

Пример (ВМ «пользователь», 100 повторов):
  python3 experiment.py --base https://192.168.56.10:8443 --scenario normal \
      --runs 100 --label "ВМ2, легитимная ТД" --csv results/normal.csv
"""
import argparse
import base64
import csv
import json
import math
import ssl
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

import httpx

from client_sim import telemetry_for, tls_context

TELEMETRY_SCENARIOS = ("normal", "clone", "rogue-ap", "evil-twin", "relay")
TOKEN_SCENARIOS = ("stolen-token", "no-cert", "forged-token")
# легитимные сценарии: любой исход, кроме ALLOW, — ложное срабатывание
LEGITIMATE = {"normal"}


def no_cert_context(ca: str) -> ssl.SSLContext:
    """TLS без сертификата устройства: так подключается посторонний узел."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    return ctx


def outcome(resp: httpx.Response) -> str:
    """Классификация ответа шлюза.

    ALLOW / SUSPICIOUS — доступ получен (вердикт из заголовка X-WG-Verdict);
    BLOCK              — 403, микросервис безопасности выявил признаки подмены;
    DENY:<причина>     — 401, отказ аутентификации (причина из ответа);
    RATE_LIMIT         — 429, ограничение частоты запросов в NGINX;
    FAIL_CLOSED        — 503, недоступна зависимость, доступ закрыт.
    """
    if resp.status_code == 200:
        return resp.headers.get("x-wg-verdict", "ALLOW")
    if resp.status_code == 403:
        return "BLOCK"
    if resp.status_code == 401:
        try:
            body = resp.json()
        except ValueError:
            body = {}
        return "DENY:" + (body.get("reason") or body.get("detail") or "unknown").replace(" ", "_")
    if resp.status_code == 429:
        return "RATE_LIMIT"
    if resp.status_code == 503:
        return "FAIL_CLOSED"
    return f"HTTP_{resp.status_code}"


def forge(token: str) -> str:
    """Меняет роль в полезной нагрузке JWT, сохраняя исходную подпись."""
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["role"] = "admin"
    forged = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode())
    return f"{header}.{forged.rstrip(b'=').decode()}.{signature}"


def upper_bound(k: int, n: int, alpha: float = 0.05) -> float:
    """Верхняя односторонняя граница доли исходов (Клоппер — Пирсон).

    Наибольшая вероятность p, при которой получить не более k исходов
    из n ещё не менее вероятно, чем alpha. При k = 0 даёт 1 - alpha^(1/n)
    («правило трёх»: примерно 3/n).
    """
    if n == 0:
        return 1.0
    if k >= n:
        return 1.0

    def cdf(p: float) -> float:
        return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))

    lo, hi = k / n, 1.0
    for _ in range(60):          # бисекция: cdf(p) монотонно убывает по p
        mid = (lo + hi) / 2
        if cdf(mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi


class Runner:
    def __init__(self, a: argparse.Namespace):
        self.a = a
        self.ctx = tls_context(a.ca, (a.cert, a.key))
        self.client = httpx.Client(base_url=a.base, verify=self.ctx, timeout=10, trust_env=False)

    def reconnect(self) -> None:
        self.client.close()
        self.client = httpx.Client(base_url=self.a.base, verify=self.ctx, timeout=10, trust_env=False)

    def login(self, telemetry: str, password: str | None = None) -> httpx.Response:
        return self.client.post("/api/login", headers={"X-WG-Telemetry": telemetry},
                                json={"username": self.a.user,
                                      "password": password or self.a.password})

    def portal(self, token: str, telemetry: str, client: httpx.Client | None = None) -> httpx.Response:
        return (client or self.client).get("/portal/profile", headers={
            "X-WG-Telemetry": telemetry, "Authorization": f"Bearer {token}"})

    def attempt(self, scenario: str, i: int) -> tuple[str, str, float]:
        """Одна попытка: (этап, исход, время ответа решающего запроса в мс)."""
        tel = telemetry_for(scenario if scenario in TELEMETRY_SCENARIOS[2:] else "normal")
        started = time.perf_counter()
        if scenario in TELEMETRY_SCENARIOS:
            r = self.login(tel)
            if r.status_code != 200:
                return "login", outcome(r), (time.perf_counter() - started) * 1000
            token = r.json()["access_token"]
            started = time.perf_counter()
            r = self.portal(token, tel)
            return "portal", outcome(r), (time.perf_counter() - started) * 1000
        if scenario == "password-guess":
            r = self.login(tel, password=f"guess-{i:04d}")
            return "login", outcome(r), (time.perf_counter() - started) * 1000
        token = Path(self.a.token_file).read_text().strip()
        if scenario == "forged-token":
            token = forge(token)
        if scenario == "no-cert":
            with httpx.Client(base_url=self.a.base, verify=no_cert_context(self.a.ca),
                              timeout=10, trust_env=False) as anon:
                r = self.portal(token, tel, anon)
        else:
            r = self.portal(token, tel)
        return "portal", outcome(r), (time.perf_counter() - started) * 1000

    def export_token(self) -> None:
        r = self.login(telemetry_for("normal"))
        if r.status_code != 200:
            sys.exit(f"вход не выполнен: {r.status_code} {r.text[:200]}")
        Path(self.a.token_file).write_text(r.json()["access_token"] + "\n")
        print(f"Токен пользователя {self.a.user} сохранён в {self.a.token_file}")


def rate_line(what: str, k: int, n: int) -> None:
    print(f"  {what}: {k} из {n} = {k / n:.1%}; верхняя 95%-я граница: {upper_bound(k, n):.1%}")


def summarize(scenario: str, label: str, rows: list[dict]) -> None:
    n = len(rows)
    counts = Counter(r["outcome"] for r in rows)
    lat = sorted(r["latency_ms"] for r in rows if not r["outcome"].startswith("NET_ERROR"))
    print(f"\n=== {scenario} | {label} | попыток: {n}")
    for name, k in counts.most_common():
        print(f"  {name:<34}{k:>5}  {k / n:7.1%}")
    # сбои сети и тайм-ауты учитываются отдельно: это вопрос доступности стенда,
    # а не решения паттерна; доли решений считаются по завершённым попыткам
    failed = sum(k for name, k in counts.items() if name.startswith("NET_ERROR"))
    if failed:
        rate_line("сбои сети и тайм-ауты (ответ не получен)", failed, n)
        n -= failed
        print(f"  доли ниже — по {n} попыткам, на которые получен ответ")
    if n == 0:
        return
    if scenario in LEGITIMATE:
        rate_line("ложные срабатывания (исход не ALLOW)", n - counts["ALLOW"], n)
    else:
        rate_line("атака не обнаружена (исход ALLOW)", counts["ALLOW"], n)
        rate_line("атака не предотвращена (доступ получен)", counts["ALLOW"] + counts["SUSPICIOUS"], n)
    p95 = lat[max(0, math.ceil(0.95 * len(lat)) - 1)]
    print(f"  время ответа, мс: среднее {statistics.mean(lat):.1f}, медиана {statistics.median(lat):.1f}, "
          f"95-й процентиль {p95:.1f}, максимум {lat[-1]:.1f}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default="https://192.168.56.10:8443")
    p.add_argument("--scenario", required=True,
                   choices=[*TELEMETRY_SCENARIOS, "export-token", *TOKEN_SCENARIOS, "password-guess"])
    # 100 повторов: если ошибок нет, их доля с вероятностью 95 % не больше 3 % (правило трёх)
    p.add_argument("--runs", type=int, default=100)
    # 0,25 с между попытками: попытка — до двух запросов, итого не более 8 запросов/с,
    # что ниже ограничения NGINX 10 запросов/с (иначе сработает 429, а не правила паттерна)
    p.add_argument("--interval", type=float, default=0.25)
    p.add_argument("--label", default="", help="подпись серии: ВМ и путь (легитимная ТД / подменная ТД)")
    p.add_argument("--csv", help="файл для результатов отдельных попыток")
    p.add_argument("--token-file", default="token.txt")
    p.add_argument("--ca", default="certs/ca.crt")
    p.add_argument("--cert", default="certs/user1.crt")
    p.add_argument("--key", default="certs/user1.key")
    p.add_argument("--user", default="ivanov")
    p.add_argument("--password", default="Ivanov#2026")
    a = p.parse_args()

    runner = Runner(a)
    if a.scenario == "export-token":
        runner.export_token()
        return

    rows = []
    for i in range(1, a.runs + 1):
        started = time.perf_counter()
        try:
            stage, result, ms = runner.attempt(a.scenario, i)
        except httpx.TransportError as exc:
            # сбой сети или тайм-аут ответа (10 с) — это тоже результат испытания:
            # попытка фиксируется, соединения открываются заново, серия продолжается
            stage, result = "network", f"NET_ERROR:{type(exc).__name__}"
            ms = (time.perf_counter() - started) * 1000
            runner.reconnect()
        rows.append({"scenario": a.scenario, "label": a.label, "run": i, "stage": stage,
                     "outcome": result, "latency_ms": round(ms, 2),
                     "ts": time.strftime("%Y-%m-%dT%H:%M:%S")})
        print(f"\r{a.scenario}: {i}/{a.runs} {result:<30}", end="", flush=True)
        if a.interval:
            time.sleep(a.interval)
    print()
    if a.csv:
        Path(a.csv).parent.mkdir(parents=True, exist_ok=True)
        with open(a.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    summarize(a.scenario, a.label, rows)


if __name__ == "__main__":
    main()
