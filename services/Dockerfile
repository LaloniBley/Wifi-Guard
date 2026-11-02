# Единый Dockerfile для Python-микросервисов паттерна.
# Сборка (из корня репозитория):
#   docker build -f services/Dockerfile --build-arg SERVICE=auth -t wifi-guard/auth:1.0.0 .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

ARG SERVICE
COPY common/wg_common ./wg_common
COPY services/${SERVICE}/wg_${SERVICE} ./wg_${SERVICE}

# непривилегированный пользователь: контейнер не запускается от root
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin wg
USER 10001

ENV PACKAGE=wg_${SERVICE} HOST=0.0.0.0 PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn ${PACKAGE}.main:app_factory --factory --host ${HOST} --port ${PORT} --no-server-header"]
