"""Подключение микросервисов к базе данных.

В кластере используется Oracle Database 23ai Free (драйвер python-oracledb
в «тонком» режиме, без Oracle Instant Client). Для автотестов и локального
запуска без кластера используется SQLite — код работы с таблицами один и тот же,
так как запросы строятся через SQLAlchemy Core.
"""
import logging
import time

from sqlalchemy import MetaData, create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

from .settings import env

log = logging.getLogger(__name__)


def build_db_url() -> str:
    """Формирует строку подключения из переменных окружения."""
    url = env("DB_URL")
    if url:
        return url
    host = env("DB_HOST")
    if not host:
        return "sqlite+pysqlite:///:memory:"
    user = env("DB_USER", required=True)
    password = env("DB_PASSWORD", required=True)
    port = env("DB_PORT", "1521")
    service = env("DB_SERVICE", "FREEPDB1")
    return f"oracle+oracledb://{user}:{password}@{host}:{port}/?service_name={service}"


def make_engine(url: str | None = None) -> Engine:
    url = url or build_db_url()
    if url.startswith("sqlite") and ":memory:" in url:
        # одна общая in-memory БД на все потоки (для тестов)
        return create_engine(url, connect_args={"check_same_thread": False},
                             poolclass=StaticPool)
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5)


def init_schema(engine: Engine, metadata: MetaData,
                attempts: int = 30, delay: float = 2.0) -> None:
    """Создаёт таблицы сервиса, ожидая готовности СУБД.

    Контейнер Oracle после запуска открывает БД 1-2 минуты, а Kubernetes
    запускает поды параллельно. Поэтому сервис делает до `attempts` попыток
    с паузой, растущей от `delay` секунд (не более 10 с): 30 попыток
    покрывают около 4 минут ожидания.
    """
    wait = delay
    for attempt in range(1, attempts + 1):
        try:
            metadata.create_all(engine)
            return
        except Exception as exc:  # noqa: BLE001 - СУБД ещё не готова
            if attempt == attempts:
                raise
            log.warning("БД недоступна (попытка %s/%s): %s", attempt, attempts, exc)
            time.sleep(wait)
            wait = min(wait * 1.5, 10.0)


def db_alive(engine: Engine) -> bool:
    """Проверка готовности для readinessProbe."""
    probe = "SELECT 1 FROM DUAL" if engine.dialect.name == "oracle" else "SELECT 1"
    try:
        with engine.connect() as conn:
            conn.execute(text(probe))
        return True
    except Exception:  # noqa: BLE001
        return False
