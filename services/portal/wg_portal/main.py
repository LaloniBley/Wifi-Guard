"""Защищаемое приложение «Корпоративный портал» (демонстрационная версия).

Принимает только запросы, прошедшие шлюз доступа: сетевые политики
Kubernetes пропускают трафик к порталу исключительно из пода шлюза,
а заголовок X-WG-User выставляет шлюз после верификации токена.
"""
import logging

from fastapi import FastAPI, Header, HTTPException

log = logging.getLogger("wg_portal")

DOCUMENTS = [
    {"id": 1, "title": "Положение о защите персональных данных", "class": "конфиденциально"},
    {"id": 2, "title": "График отпусков 2026", "class": "для служебного пользования"},
]


def create_app() -> FastAPI:
    app = FastAPI(title="Корпоративный портал")

    def require_user(user: str | None) -> str:
        if not user:
            raise HTTPException(403, "request did not pass the access gateway")
        return user

    @app.get("/portal/profile")
    def profile(x_wg_user: str | None = Header(default=None),
                x_wg_verdict: str | None = Header(default=None)):
        user = require_user(x_wg_user)
        return {"user": user, "department": "ИТ", "verdict": x_wg_verdict}

    @app.get("/portal/documents")
    def documents(x_wg_user: str | None = Header(default=None)):
        require_user(x_wg_user)
        return DOCUMENTS

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app


def app_factory() -> FastAPI:
    logging.basicConfig(level=logging.INFO)
    return create_app()
