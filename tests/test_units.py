"""Модульные тесты вспомогательных функций шлюза, TTL-зонда и аутентификации."""
import base64
import socket
import struct
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from client_sim import encode_telemetry
from conftest import make_cert_pem
from wg_auth.passwords import hash_password, verify_password
from wg_auth.tokens import TokenError, check_token, issue_token
from wg_common.netutil import normalize_mac
from wg_gateway.context import bearer_token, cert_thumbprint, parse_telemetry
from wg_ttlprobe.probe import TtlTable, hops_from_ttl, initial_ttl, parse_ipv4_tcp

SECRET = "x" * 32


def test_normalize_mac_formats():
    assert normalize_mac("A0-B1-C2-D3-E4-01") == "a0:b1:c2:d3:e4:01"
    assert normalize_mac("a0b1.c2d3.e401") == "a0:b1:c2:d3:e4:01"
    assert normalize_mac("not-a-mac") is None


def test_cert_thumbprint_matches_x5t_s256():
    pem = make_cert_pem("user1")
    cert = x509.load_pem_x509_certificate(pem.encode())
    expected = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).rstrip(b"=").decode()
    assert cert_thumbprint(quote(pem)) == expected
    assert cert_thumbprint("garbage") is None


def test_parse_telemetry_roundtrip_and_garbage():
    t = parse_telemetry(encode_telemetry("CORP-WIFI", "A0B1C2D3E401", True, []))
    assert t == {"ssid": "CORP-WIFI", "bssid": "a0:b1:c2:d3:e4:01", "pmf": True, "scan": []}
    assert parse_telemetry("@@@")["bssid"] is None


def test_bearer_token():
    assert bearer_token("Bearer abc") == "abc"
    assert bearer_token("Basic abc") is None


def test_ttl_to_hops():
    assert (initial_ttl(62), hops_from_ttl(62)) == (64, 2)
    assert hops_from_ttl(126) == 2      # Windows-клиент
    assert hops_from_ttl(64) == 0


def test_parse_ipv4_tcp_packet():
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 61, 6, 0,
                            socket.inet_aton("10.10.0.15"), socket.inet_aton("10.244.0.7"))
    tcp_header = struct.pack("!HH", 51515, 8443) + b"\x00" * 16
    assert parse_ipv4_tcp(ip_header + tcp_header) == ("10.10.0.15", 61, 8443)
    assert parse_ipv4_tcp(b"\x60" + b"\x00" * 39) is None   # IPv6 игнорируется


def test_ttl_table_eviction():
    t = TtlTable(max_entries=2)
    t.put("a", 60); t.put("b", 61); t.put("c", 62)  # noqa: E702
    assert t.get("a") is None and t.get("c") == 62


def test_password_hash_and_verify():
    h = hash_password("Secret#1", iterations=1000)
    assert verify_password("Secret#1", h) and not verify_password("secret#1", h)


def test_token_binding_mismatch():
    token, _ = issue_token(SECRET, "ivanov", "user", "fp-user", "a0:b1:c2:d3:e4:01", 2, 60)
    assert check_token(SECRET, token, "fp-user")["sub"] == "ivanov"
    for fp, reason in (("fp-attacker", "binding_mismatch"), (None, "no_client_certificate")):
        try:
            check_token(SECRET, token, fp)
            raise AssertionError("ожидался отказ")
        except TokenError as err:
            assert err.reason == reason


def test_expired_and_forged_tokens():
    token, _ = issue_token(SECRET, "ivanov", "user", "fp", None, None, -1)
    for tok, secret, reason in ((token, SECRET, "token_expired"),
                                (token, "y" * 32, "token_invalid")):
        try:
            check_token(secret, tok, "fp")
            raise AssertionError
        except TokenError as err:
            assert err.reason == reason


def test_audit_series_start_at_zero():
    # без нулевых рядов первая атака не видна функции increase() в Prometheus
    from wg_audit.main import Metrics
    from prometheus_client import generate_latest
    text = generate_latest(Metrics().registry).decode()
    assert 'wg_verdicts_total{mode="request",verdict="BLOCK"} 0.0' in text
    assert 'wg_indicators_total{indicator="TWIN_IN_AIR",scenario="C1"} 0.0' in text
    assert 'wg_auth_failures_total{reason="binding_mismatch"} 0.0' in text


def test_forged_token_fails_signature_check():
    from experiment import forge
    token, _ = issue_token(SECRET, "ivanov", "user", "fp", None, None, 600)
    forged = forge(token)
    assert forged.split(".")[2] == token.split(".")[2]      # подпись не изменена
    try:
        check_token(SECRET, forged, "fp")
        raise AssertionError
    except TokenError as err:
        assert err.reason == "token_invalid"


def test_upper_bound_rule_of_three():
    from experiment import upper_bound
    # 0 ошибок из 100: доля ошибок с вероятностью 95 % не больше 3 %
    assert abs(upper_bound(0, 100) - (1 - 0.05 ** (1 / 100))) < 1e-9
    assert 0.029 < upper_bound(0, 100) < 0.030
    assert upper_bound(5, 100) > 0.05
