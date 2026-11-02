"""Сетевые вспомогательные функции."""
import re

_MAC_RE = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value: str | None) -> str | None:
    """Приводит MAC-адрес (BSSID) к виду aa:bb:cc:dd:ee:ff.

    Клиенты разных ОС передают BSSID в разных форматах
    (AA-BB-CC-DD-EE-FF, aabb.ccdd.eeff, AA:BB:...). Для сверки с реестром
    доверенных ТД все значения приводятся к одному виду.
    Возвращает None, если строка не является MAC-адресом.
    """
    if not value:
        return None
    hex_only = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    if not _MAC_RE.match(hex_only):
        return None
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2))
