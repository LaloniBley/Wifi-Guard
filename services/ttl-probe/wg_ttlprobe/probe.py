"""TTL-зонд шлюза доступа: определение числа транзитных узлов до клиента.

Запускается вторым контейнером в поде шлюза и разделяет с ним сетевое
пространство имён пода. Читает входящие IPv4-пакеты, адресованные порту
шлюза, через сырой сокет AF_PACKET (требуется только capability NET_RAW)
и запоминает TTL последнего пакета от каждого IP-адреса клиента.

HTTP API (только на 127.0.0.1, т.е. доступно лишь соседним контейнерам пода):
  GET /hops?ip=<адрес>  -> {"ip":..., "ttl":..., "initial_ttl":..., "hops":...}
  GET /healthz

Используется только стандартная библиотека Python.
"""
import json
import os
import socket
import struct
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ETH_P_IP = 0x0800
# Начальные значения TTL, используемые распространёнными ОС:
# 64 — Linux, Android, iOS, macOS; 128 — Windows; 255 — сетевое оборудование.
# 32 — устаревшие системы (Windows 95/98).
INITIAL_TTLS = (32, 64, 128, 255)
MAX_ENTRIES = 10_000   # ~2 МБ памяти (≈200 байт на запись); с запасом на все устройства организации
ENTRY_LIFETIME = 300   # с; значение TTL старше 5 мин считается неактуальным


def initial_ttl(observed: int) -> int:
    """Наименьшее стандартное начальное значение TTL, не меньшее наблюдаемого."""
    for value in INITIAL_TTLS:
        if observed <= value:
            return value
    return 255


def hops_from_ttl(observed: int) -> int:
    """Число транзитных узлов = начальный TTL - наблюдаемый TTL."""
    return initial_ttl(observed) - observed


def parse_ipv4_tcp(packet: bytes) -> tuple[str, int, int] | None:
    """Разбирает IPv4-пакет; возвращает (IP источника, TTL, порт назначения)
    для TCP-пакетов или None для остальных."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4          # длина IP-заголовка в байтах
    ttl = packet[8]
    proto = packet[9]
    if proto != 6 or len(packet) < ihl + 4:  # 6 = TCP
        return None
    src_ip = socket.inet_ntoa(packet[12:16])
    dst_port = struct.unpack("!H", packet[ihl + 2:ihl + 4])[0]
    return src_ip, ttl, dst_port


class TtlTable:
    """Таблица «IP-адрес -> (TTL, время)» с вытеснением самых старых записей."""

    def __init__(self, max_entries: int = MAX_ENTRIES):
        self._items: OrderedDict[str, tuple[int, float]] = OrderedDict()
        self._lock = threading.Lock()
        self.max_entries = max_entries

    def put(self, ip: str, ttl: int) -> None:
        with self._lock:
            self._items[ip] = (ttl, time.time())
            self._items.move_to_end(ip)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def get(self, ip: str) -> int | None:
        with self._lock:
            item = self._items.get(ip)
        if item is None or time.time() - item[1] > ENTRY_LIFETIME:
            return None
        return item[0]


def sniff(table: TtlTable, port: int) -> None:
    """Бесконечный цикл чтения пакетов из сырого сокета."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))
    while True:
        packet, _ = sock.recvfrom(65535)
        parsed = parse_ipv4_tcp(packet)
        if parsed and parsed[2] == port:
            table.put(parsed[0], parsed[1])


def make_handler(table: TtlTable):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: dict):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            url = urlparse(self.path)
            if url.path == "/healthz":
                return self._send(200, {"status": "ok"})
            if url.path != "/hops":
                return self._send(404, {"detail": "not found"})
            ip = (parse_qs(url.query).get("ip") or [""])[0]
            ttl = table.get(ip)
            if ttl is None:
                return self._send(404, {"ip": ip, "detail": "no data"})
            return self._send(200, {"ip": ip, "ttl": ttl,
                                    "initial_ttl": initial_ttl(ttl),
                                    "hops": hops_from_ttl(ttl)})

        def log_message(self, *args):  # не засорять журнал каждым запросом
            pass
    return Handler


def main() -> None:
    port = int(os.getenv("WATCH_PORT", "8443"))       # порт TLS-терминатора шлюза
    listen = int(os.getenv("PROBE_PORT", "9100"))
    table = TtlTable()
    threading.Thread(target=sniff, args=(table, port), daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", listen), make_handler(table)).serve_forever()


if __name__ == "__main__":
    main()
