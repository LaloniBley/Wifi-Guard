"""Модульные тесты правил микросервиса безопасности."""
from wg_security.rules import assess

AP = {"bssid": "a0:b1:c2:d3:e4:01", "ssid": "CORP-WIFI", "channel": 36,
      "security": "WPA3-SAE", "pmf_required": True, "ref_hops": 2}
LEGIT_SCAN = [{"ssid": "CORP-WIFI", "bssid": AP["bssid"], "channel": 36, "security": "WPA3-SAE"}]


def tel(**kw):
    base = {"ssid": "CORP-WIFI", "bssid": AP["bssid"], "pmf": True, "scan": LEGIT_SCAN}
    base.update(kw)
    return base


def test_legitimate_client_allowed():
    r = assess(tel(), 2, AP, [AP])
    assert (r.verdict, r.score, r.indicators) == ("ALLOW", 0.0, [])


def test_unknown_bssid_blocked():
    r = assess(tel(bssid="de:ad:be:ef:00:01"), 2, None, [AP])
    assert r.verdict == "BLOCK" and "BSSID_UNTRUSTED" in r.indicators and r.scenario == "C1"


def test_missing_telemetry_blocked():
    r = assess({"ssid": None, "bssid": None, "pmf": None, "scan": []}, None, None, [])
    assert r.verdict == "BLOCK"


def test_bssid_of_other_network_blocked():
    r = assess(tel(ssid="GUEST"), 2, AP, [])
    assert r.indicators == ["BSSID_UNTRUSTED"]


def test_pmf_not_negotiated_blocked():
    r = assess(tel(pmf=False), 2, AP, [AP])
    assert r.verdict == "BLOCK" and r.indicators == ["PMF_NOT_NEGOTIATED"]


def test_single_weak_indicator_is_suspicious():
    r = assess(tel(), 4, AP, [AP])
    assert (r.verdict, r.indicators, r.scenario) == ("SUSPICIOUS", ["HOPS_DEVIATION"], "C2")


def test_twin_in_air_only_is_suspicious():
    scan = LEGIT_SCAN + [{"ssid": "CORP-WIFI", "bssid": AP["bssid"], "channel": 6}]
    r = assess(tel(scan=scan), 2, AP, [AP])
    assert r.verdict == "SUSPICIOUS" and r.details["twins"][0]["why"] == "cloned_bssid_other_channel"


def test_two_weak_indicators_blocked():
    scan = LEGIT_SCAN + [{"ssid": "CORP-WIFI", "bssid": "11:22:33:44:55:66", "channel": 36}]
    r = assess(tel(scan=scan), 3, AP, [AP])
    assert r.verdict == "BLOCK" and r.score == 0.8


def test_downgraded_security_twin_detected():
    scan = LEGIT_SCAN + [{"ssid": "CORP-WIFI", "bssid": AP["bssid"], "channel": 36,
                          "security": "WPA2-PSK"}]
    r = assess(tel(scan=scan), 2, AP, [AP])
    assert r.details["twins"][0]["why"] == "cloned_bssid_downgraded_security"


def test_no_probe_data_does_not_trigger_hops():
    r = assess(tel(), None, AP, [AP])
    assert r.verdict == "ALLOW"
