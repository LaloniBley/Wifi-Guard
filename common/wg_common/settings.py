"""Чтение настроек микросервисов из переменных окружения.

В Kubernetes переменные задаются в манифестах Deployment (ConfigMap/Secret),
поэтому код не содержит адресов, паролей и ключей.
"""
import os


def env(name: str, default: str | None = None, required: bool = False) -> str | None:
    value = os.getenv(name, default)
    if required and not value:
        raise RuntimeError(f"Не задана обязательная переменная окружения {name}")
    return value


def env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def env_float(name: str, default: float) -> float:
    return float(os.getenv(name, str(default)))
