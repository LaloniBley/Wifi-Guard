"""Время первого срабатывания оповещений Prometheus за последние N часов (глава 4).

Запуск на ВМ3 при работающем пробросе порта Prometheus (127.0.0.1:9090):
  python3 scripts/lab/alert-times.py [часов, по умолчанию 3]
Печатает для каждого оповещения моменты перехода в состояние firing.
Их сравнивают со временем первой попытки серии из CSV (колонка ts).
"""
import json
import sys
import time
import urllib.parse
import urllib.request

hours = float(sys.argv[1]) if len(sys.argv) > 1 else 3
end = time.time()
query = urllib.parse.urlencode({"query": 'ALERTS{alertstate="firing"}', "start": end - hours * 3600,
                                "end": end, "step": 15})
data = json.load(urllib.request.urlopen(f"http://127.0.0.1:9090/api/v1/query_range?{query}"))
for series in sorted(data["data"]["result"], key=lambda s: s["values"][0][0]):
    name = series["metric"]["alertname"]
    starts, prev = [], None
    for ts, _ in series["values"]:
        if prev is None or ts - prev > 15:          # разрыв ряда = новое срабатывание
            starts.append(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)))
        prev = ts
    print(f"{name:<20} {series['metric'].get('severity', ''):<9} сработало: {', '.join(starts)}")
