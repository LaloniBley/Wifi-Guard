"""Генератор дашборда Grafana «WiFi-Guard — метрики безопасности».

Дашборд описан кодом, чтобы панели и запросы PromQL было удобно проверять
и изменять. Результат записывается в deploy/k8s/monitoring/wifi-guard-security.json
и загружается в Grafana при развертывании (provisioning).

Запуск: python scripts/build-dashboard.py
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "deploy/k8s/monitoring/wifi-guard-security.json"
DS = {"type": "prometheus", "uid": "prometheus"}
COLORS = {"ALLOW": "green", "SUSPICIOUS": "orange", "BLOCK": "red",
          "200": "green", "401": "yellow", "403": "red", "503": "purple"}

_ids = iter(range(1, 100))


def target(expr: str, legend: str = "", instant: bool = False, fmt: str = "time_series",
           ref: str = "A") -> dict:
    return {"refId": ref, "datasource": DS, "expr": expr, "legendFormat": legend,
            "instant": instant, "range": not instant, "format": fmt}


def color_overrides(names) -> list:
    return [{"matcher": {"id": "byName", "options": n},
             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": COLORS[n]}}]}
            for n in names]


def stat(title, expr, x, y, unit="none", red_from=1, desc="", decimals=0):
    steps = [{"color": "green", "value": None}]
    if red_from is not None:
        steps.append({"color": "red", "value": red_from})
    return {
        "id": next(_ids), "type": "stat", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"h": 4, "w": 4, "x": x, "y": y},
        "targets": [target(expr, instant=True)],
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "colorMode": "background", "graphMode": "none", "textMode": "value",
                    "justifyMode": "center", "orientation": "auto"},
        "fieldConfig": {"defaults": {"unit": unit, "decimals": decimals, "noValue": "0",
                                     "color": {"mode": "thresholds"},
                                     "thresholds": {"mode": "absolute", "steps": steps}},
                        "overrides": []},
    }


def timeseries(title, targets, x, y, w=12, h=8, unit="short", colors=(), desc="", stack=False):
    custom = {"drawStyle": "line", "lineWidth": 2, "fillOpacity": 25, "showPoints": "never",
              "spanNulls": True}
    if stack:
        custom["stacking"] = {"mode": "normal", "group": "A"}
    return {
        "id": next(_ids), "type": "timeseries", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": targets,
        "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
        "fieldConfig": {"defaults": {"unit": unit, "min": 0, "custom": custom,
                                     "color": {"mode": "palette-classic"}},
                        "overrides": color_overrides(colors)},
    }


def bargauge(title, targets, x, y, w=8, h=8, desc="", color="red"):
    return {
        "id": next(_ids), "type": "bargauge", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": targets,
        "options": {"orientation": "horizontal", "displayMode": "gradient", "showUnfilled": True,
                    "valueMode": "color", "namePlacement": "left", "sizing": "auto",
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
        "fieldConfig": {"defaults": {"unit": "none", "decimals": 0, "min": 0,
                                     "color": {"mode": "fixed", "fixedColor": color},
                                     "thresholds": {"mode": "absolute",
                                                    "steps": [{"color": color, "value": None}]}},
                        "overrides": []},
    }


R = "[$__range]"   # окно = выбранный на дашборде интервал времени


def growth(selector: str, by: str = "") -> str:
    """Точный прирост счётчика за интервал дашборда.

    increase() экстраполирует прирост на границы окна и при редких событиях
    даёт дробные значения (13,3 вместо 10 блокировок). Разность максимума
    и минимума ряда за окно равна фактическому числу событий; счётчики
    создаются аудитом с нулевым значением, поэтому первое событие учитывается.
    """
    grouping = f" by ({by})" if by else ""
    return f"sum{grouping} (max_over_time({selector}{R}) - min_over_time({selector}{R}))"
panels = [
    # --- строка 1: ключевые показатели за выбранный интервал ---
    stat("Заблокировано запросов", growth('wg_verdicts_total{verdict="BLOCK"}'), 0, 0,
         desc="Вердикты BLOCK: доступ нарушителя к приложению предотвращён"),
    stat("Подозрительных запросов", growth('wg_verdicts_total{verdict="SUSPICIOUS"}'), 4, 0,
         desc="Вердикты SUSPICIOUS: один слабый признак, запрос пропущен с усиленным журналированием"),
    stat("Чужой токен (С2)", growth('wg_auth_failures_total{reason="binding_mismatch"}'), 8, 0,
         desc="Токен предъявлен с устройства, к сертификату которого он не привязан"),
    stat("Отозвано сессий", growth("wg_sessions_revoked_total"), 12, 0,
         desc="Сессии, прекращённые микросервисом безопасности после вердикта BLOCK"),
    stat("Доля блокировок",
         growth('wg_verdicts_total{verdict="BLOCK"}') + " / (" + growth("wg_verdicts_total") + " > 0)",
         16, 0, unit="percentunit", red_from=None, decimals=1,
         desc="Доля заблокированных среди всех оценённых запросов"),
    stat("Активные оповещения", 'count(ALERTS{alertstate="firing"}) or vector(0)', 20, 0,
         desc="Сработавшие правила оповещения Prometheus"),
    # --- строка 2: динамика ---
    timeseries("Вердикты микросервиса безопасности, событий в минуту",
               [target("sum by (verdict) (rate(wg_verdicts_total[1m])) * 60", "{{verdict}}")],
               0, 4, colors=("ALLOW", "SUSPICIOUS", "BLOCK"), stack=True),
    timeseries("Срабатывания индикаторов подмены, в минуту",
               [target("sum by (indicator) (rate(wg_indicators_total[1m])) * 60", "{{indicator}}")],
               12, 4),
    # --- строка 3: структура атак за интервал ---
    bargauge("Индикаторы подмены за интервал",
             [target(growth("wg_indicators_total", "indicator"), "{{indicator}}",
                     instant=True)], 0, 12),
    bargauge("Отказы аутентификации по причинам",
             [target(growth("wg_auth_failures_total", "reason") + " > 0", "{{reason}}",
                     instant=True)], 8, 12, color="orange"),
    bargauge("Срабатывания по сценариям угрозы УБИ.126",
             [target(growth('wg_indicators_total{scenario="C1"}'), "С1 подмена ТД",
                     instant=True, ref="A"),
              target(growth('wg_auth_failures_total{reason="binding_mismatch"}') + " + "
                     + growth('wg_indicators_total{scenario="C2"}'),
                     "С2 подмена клиента", instant=True, ref="B")], 16, 12, color="purple"),
    # --- строка 4: работа шлюза ---
    timeseries("Ответы шлюза по кодам, в минуту",
               [target("sum by (status) (rate(wg_gateway_requests_total[1m])) * 60", "{{status}}")],
               0, 20, w=8, colors=("200", "401", "403", "503")),
    timeseries("Время обработки запроса шлюзом",
               [target("histogram_quantile(0.5, sum by (le) (rate(wg_gateway_latency_seconds_bucket[1m])))",
                       "p50", ref="A"),
                target("histogram_quantile(0.95, sum by (le) (rate(wg_gateway_latency_seconds_bucket[1m])))",
                       "p95", ref="B")], 8, 20, w=8, unit="s"),
    bargauge("Распределение оценки риска",
             [target(growth("wg_risk_score_bucket", "le"), "до {{le}}", instant=True,
                     fmt="heatmap")], 16, 20, color="blue",
             desc="Число оценок риска по интервалам: 0 — ALLOW, 0,4 — SUSPICIOUS, 0,8 и выше — BLOCK"),
    # --- строка 5: оповещения ---
    {
        "id": next(_ids), "type": "table", "title": "Сработавшие оповещения", "datasource": DS,
        "gridPos": {"h": 6, "w": 24, "x": 0, "y": 28},
        "targets": [target('ALERTS{alertstate="firing"}', instant=True, fmt="table")],
        "transformations": [{"id": "organize", "options": {
            "excludeByName": {"Time": True, "Value": True, "__name__": True, "alertstate": True},
            "renameByName": {"alertname": "Оповещение", "severity": "Важность",
                             "scenario": "Сценарий", "threat": "Угроза"},
            "indexByName": {"alertname": 0, "severity": 1, "threat": 2, "scenario": 3}}}],
        "options": {"showHeader": True, "cellHeight": "sm"},
        "fieldConfig": {"defaults": {}, "overrides": []},
    },
]

dashboard = {
    "uid": "wifi-guard-security",
    "title": "WiFi-Guard — метрики безопасности",
    "description": "Мониторинг защиты приложения от подмены беспроводного клиента или точки доступа (УБИ.126)",
    "tags": ["wifi-guard", "security"],
    "timezone": "browser",
    "editable": False,
    "graphTooltip": 1,
    "refresh": "10s",
    "time": {"from": "now-30m", "to": "now"},
    "timepicker": {"refresh_intervals": ["5s", "10s", "30s", "1m", "5m"]},
    "schemaVersion": 39,
    "version": 1,
    "templating": {"list": []},
    "annotations": {"list": []},
    "panels": panels,
}

if __name__ == "__main__":
    OUT.write_text(json.dumps(dashboard, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{OUT} — панелей: {len(panels)}")
