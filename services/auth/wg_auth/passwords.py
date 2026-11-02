"""Хеширование и проверка паролей пользователей (PBKDF2-HMAC-SHA256)."""
import base64
import hashlib
import hmac
import os

# 600 000 итераций — значение, рекомендованное OWASP Password Storage
# Cheat Sheet для PBKDF2-HMAC-SHA256; переопределяется переменной окружения
# только для ускорения автотестов.
PBKDF2_ITERATIONS = int(os.getenv("PBKDF2_ITERATIONS", "600000"))
SALT_BYTES = 16  # 128 бит соли — минимум по NIST SP 800-132


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Возвращает строку вида pbkdf2_sha256$<итерации>$<соль>$<хеш>."""
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    """Сравнивает пароль с сохранённым хешем за постоянное время."""
    try:
        algo, iterations, salt_b64, hash_b64 = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(hash_b64)
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
    return hmac.compare_digest(actual, expected)
