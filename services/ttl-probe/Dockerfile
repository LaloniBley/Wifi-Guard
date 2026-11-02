# TTL-зонд: только стандартная библиотека Python, без зависимостей.
# Запускается от root внутри контейнера, но с единственной capability NET_RAW
# (остальные сброшены в манифесте Kubernetes).
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY services/ttl-probe/wg_ttlprobe ./wg_ttlprobe
CMD ["python", "-m", "wg_ttlprobe.probe"]
