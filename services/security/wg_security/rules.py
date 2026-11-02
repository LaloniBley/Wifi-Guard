"""Правила обнаружения признаков подмены ТД или беспроводного клиента.

Функция assess() не обращается к сети и БД: на вход подаются атрибуты
подключения и эталонные данные из реестра, на выход — оценка риска,
список сработавших индикаторов и вердикт. Это позволяет проверять правила
модульными тестами (глава 4) и объяснять каждое решение (правила
интерпретируемы, в отличие от моделей машинного обучения).

Индикаторы и их веса:
  K1 BSSID_UNTRUSTED     1.0  ТД отсутствует в реестре или принадлежит другой сети;
  K2 PMF_NOT_NEGOTIATED  1.0  реестр требует PMF (802.11w), а в ассоциации его нет;
  N1 HOPS_DEVIATION      0.4  число транзитных узлов отличается от эталона ТД;
  N2 TWIN_IN_AIR         0.4  в эфире виден двойник: тот же SSID с BSSID не из
                              реестра или доверенный BSSID на чужом канале/с иной
                              защитой.
Критический индикатор (K) достаточен для блокировки. Слабый (N) сам по себе
даёт вердикт «подозрительно» (запрос пропускается, журналирование усилено);
два слабых индикатора вместе дают блокировку: 0.4 + 0.4 = 0.8 >= порога.
"""
from dataclasses import dataclass, field

from wg_common.netutil import normalize_mac

WEIGHTS = {
    "BSSID_UNTRUSTED": 1.0,
    "PMF_NOT_NEGOTIATED": 1.0,
    "HOPS_DEVIATION": 0.4,
    "TWIN_IN_AIR": 0.4,
}
C1_INDICATORS = {"BSSID_UNTRUSTED", "PMF_NOT_NEGOTIATED", "TWIN_IN_AIR"}


@dataclass
class Config:
    suspicious_threshold: float = 0.4   # один слабый индикатор
    block_threshold: float = 0.8        # два слабых или один критический
    hops_tolerance: int = 0             # маршрут ТД -> сервер в ЛВС статичен


@dataclass
class Assessment:
    verdict: str                        # ALLOW | SUSPICIOUS | BLOCK
    score: float
    indicators: list[str] = field(default_factory=list)
    scenario: str | None = None         # C1 | C2 | None
    details: dict = field(default_factory=dict)


def find_twins(scan: list[dict], ssid: str, ap: dict | None,
               trusted_bssids: set[str]) -> list[dict]:
    """Ищет в списке видимых сетей признаки «злого двойника»."""
    twins = []
    for net in scan or []:
        bssid = normalize_mac(net.get("bssid"))
        if net.get("ssid") != ssid or bssid is None:
            continue
        if bssid not in trusted_bssids:
            twins.append({"bssid": bssid, "why": "unknown_bssid_same_ssid"})
        elif ap and bssid == ap["bssid"]:
            if net.get("channel") not in (None, ap["channel"]):
                twins.append({"bssid": bssid, "why": "cloned_bssid_other_channel"})
            elif net.get("security") not in (None, ap["security"]):
                twins.append({"bssid": bssid, "why": "cloned_bssid_downgraded_security"})
    return twins


def assess(telemetry: dict, hops: int | None, ap: dict | None,
           ssid_aps: list[dict], cfg: Config = Config()) -> Assessment:
    indicators: list[str] = []
    details: dict = {}
    ssid = telemetry.get("ssid")

    # K1: точка доступа должна быть в реестре и относиться к той же сети
    if ap is None or ap["ssid"] != ssid:
        indicators.append("BSSID_UNTRUSTED")
    else:
        # K2: подменная ТД, как правило, не согласует защиту управляющих кадров
        if ap["pmf_required"] and telemetry.get("pmf") is not True:
            indicators.append("PMF_NOT_NEGOTIATED")
        # N1: ретрансляция через узел нарушителя меняет длину маршрута
        if hops is not None and ap.get("ref_hops") is not None:
            deviation = abs(hops - ap["ref_hops"])
            details["hops"] = {"observed": hops, "reference": ap["ref_hops"]}
            if deviation > cfg.hops_tolerance:
                indicators.append("HOPS_DEVIATION")

    # N2: двойник в эфире (по списку сетей, видимых клиенту)
    trusted = {a["bssid"] for a in ssid_aps}
    twins = find_twins(telemetry.get("scan") or [], ssid, ap, trusted)
    if twins:
        indicators.append("TWIN_IN_AIR")
        details["twins"] = twins

    score = min(1.0, round(sum(WEIGHTS[i] for i in indicators), 2))
    if score >= cfg.block_threshold:
        verdict = "BLOCK"
    elif score >= cfg.suspicious_threshold:
        verdict = "SUSPICIOUS"
    else:
        verdict = "ALLOW"

    scenario = None
    if indicators:
        scenario = "C1" if C1_INDICATORS & set(indicators) else "C2"
    return Assessment(verdict, score, indicators, scenario, details)
