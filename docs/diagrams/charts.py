"""Блок-схемы алгоритмов микросервисов (рисунки 9–14 главы 3)."""
import sys
from pathlib import Path

from flowchart import Chart, H, W

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
DY = 3.4          # шаг по вертикали между символами
XR = 9.0          # колонка ответвлений
LANE = XR + W / 2 + 1.6   # обходная вертикаль справа от колонки ответвлений


def ys(n, extra=None):
    """Координаты символов по вертикали; extra = {номер: доп. зазор} — там,
    где в линию над символом вливаются ответвления."""
    extra = extra or {}
    out, y = [], 0.0
    for i in range(n):
        y -= extra.get(i, 0.0)
        out.append(y)
        y -= DY
    return out


def merge_back(c, box, y_merge, x_main=0.0):
    """Линия от символа ответвления вниз и влево к основной линии."""
    bx = c.nodes[box]["x"]
    c.edges.append(dict(a=box, b=None, src="bottom", dst=None,
                        via=[(bx, y_merge), (x_main, y_merge)], label=None,
                        label_at=None, arrow=True, free=True))


def patch_free_edges(c):
    """Поддержка линий, оканчивающихся на основной линии (слияние, п. 4.2.3)."""
    orig = c.draw_edge

    def draw(ax, e):
        if not e.get("free"):
            return orig(ax, e)
        p0 = c.port(e["a"], e["src"])
        pts = [p0] + e["via"]
        xs, ys_ = zip(*pts)
        ax.plot(xs, ys_, color="black", lw=0.9)
        if e.get("label"):
            from flowchart import FS
            ax.text(p0[0] + 0.25, p0[1] + 0.25, e["label"], fontsize=FS - 0.5,
                    family="Liberation Serif", ha="left", va="center")
        if not e["arrow"]:
            return
        (ax0, ay0), (bx, by) = pts[-2], pts[-1]
        length = max(abs(bx - ax0), abs(by - ay0))
        k = min(0.45, length) / length
        ax.annotate("", xy=(bx, by), xytext=(bx - (bx - ax0) * k, by - (by - ay0) * k),
                    arrowprops=dict(arrowstyle="-|>", color="black", lw=0.9,
                                    mutation_scale=9, shrinkA=0, shrinkB=0))
    c.draw_edge = draw


def above(y_node, k=0):
    """Точка слияния над символом с центром y_node: выше его входной стрелки."""
    return y_node + H / 2 + 0.65 + 0.3 * k


def chain(c, ids):
    for a, b in zip(ids, ids[1:]):
        c.edge(a, b)


# ---------------------------------------------------------------- рис. 9: шлюз
def gateway():
    c = Chart(); patch_free_edges(c)
    y = ys(12, {10: 0.6})
    c.node("s", "term", "Начало", 0, y[0])
    c.node("in", "io", "Запрос: сертификат,\nтокен, телеметрия Wi-Fi", 0, y[1])
    c.node("d1", "dec", "Сертификат\nпроверен?", 0, y[2])
    c.node("fp", "proc", "Вычислить отпечаток\nсертификата x5t#S256", 0, y[3])
    c.node("hops", "pred", "Запросить число\nтранзитных узлов\nу TTL-зонда", 0, y[4])
    c.node("ver", "pred", "Проверить токен в\nмикросервисе\nаутентификации", 0, y[5])
    c.node("d2", "dec", "Токен\nдействителен?", 0, y[6])
    c.node("sec", "pred", "Получить вердикт\nмикросервиса\nбезопасности", 0, y[7])
    c.node("d3", "dec", "Вердикт\nBLOCK?", 0, y[8])
    c.node("px", "proc", "Передать запрос в\n«Корпоративный портал»", 0, y[9])
    c.node("out", "io", "Ответ клиенту", 0, y[10])
    c.node("e", "term", "Конец", 0, y[11])
    c.node("r1", "proc", "Ответ 401: требуется\nсертификат устройства", XR, y[2])
    c.node("r2", "proc", "Ответ 401: токен\nотклонён (причина)", XR, y[6])
    c.node("r3", "proc", "Ответ 403: признаки\nподмены узла", XR, y[8])
    for i, r in enumerate(["r1", "r2", "r3"]):
        c.node(f"c{i}", "conn", "1", XR, c.nodes[r]["y"] - H / 2 - 1.6)
        c.edge(r, f"c{i}")
    c.node("ci", "conn", "1", -XR, above(y[10]))
    chain(c, ["s", "in", "d1"])
    c.edge("d1", "fp", label="да")
    chain(c, ["fp", "hops", "ver", "d2"])
    c.edge("d2", "sec", label="да")
    c.edge("sec", "d3")
    c.edge("d3", "px", label="нет")
    chain(c, ["px", "out", "e"])
    c.edge("d1", "r1", src="right", dst="left", label="нет")
    c.edge("d2", "r2", src="right", dst="left", label="нет")
    c.edge("d3", "r3", src="right", dst="left", label="да")
    c.edges.append(dict(a="ci", b=None, src="right", dst=None,
                        via=[(0, c.nodes["ci"]["y"])], label=None, label_at=None,
                        arrow=True, free=True))
    c.render(OUT / "fig09_gateway.png")


# ---------------------------------------------------------------- рис. 10: TTL-зонд
def ttl_probe():
    c = Chart(); patch_free_edges(c)
    y = ys(10, {8: 1.0})
    c.node("s", "term", "Начало", 0, y[0])
    c.node("sock", "prep", "Открыть сырой сокет\nAF_PACKET (IPv4)", 0, y[1])
    c.node("ls", "loop_start", "Цикл A: пока\nсервис запущен", 0, y[2])
    c.node("rx", "io", "Принять пакет", 0, y[3])
    c.node("d1", "dec", "IPv4 и TCP?", 0, y[4])
    c.node("d2", "dec", "Порт\nназначения 8443?", 0, y[5])
    c.node("ext", "proc", "IP = байты 12–15;\nTTL = байт 8", 0, y[6])
    c.node("put", "pred", "Сохранить IP, TTL\nи время в таблице,\nвытеснить старые", 0, y[7])
    c.node("le", "loop_end", "Цикл A", 0, y[8])
    c.node("e", "term", "Конец", 0, y[9])
    chain(c, ["s", "sock", "ls", "rx", "d1"])
    c.edge("d1", "d2", label="да")
    c.edge("d2", "ext", label="да")
    chain(c, ["ext", "put", "le", "e"])
    ym1 = above(y[8], 0)      # внешняя обходная линия — ниже
    ym2 = above(y[8], 1)      # внутренняя — выше, линии не пересекаются
    c.edges.append(dict(a="d1", b=None, src="right", dst=None,
                        via=[(XR - 2, y[4]), (XR - 2, ym1), (0, ym1)], label="нет",
                        label_at=None, arrow=True, free=True))
    c.edges.append(dict(a="d2", b=None, src="right", dst=None,
                        via=[(XR - 3, y[5]), (XR - 3, ym2), (0, ym2)], label="нет",
                        label_at=None, arrow=True, free=True))
    # б) обработка запроса GET /hops
    x2 = XR + W / 2 + 1.5
    y2 = ys(9, {7: 0.6})
    c.node("s2", "term", "Начало", x2, y2[0])
    c.node("in2", "io", "IP-адрес клиента", x2, y2[1])
    c.node("get", "proc", "TTL = таблица[IP]", x2, y2[2])
    c.node("d3", "dec", "Запись есть и\nне старше 300 с?", x2, y2[3])
    c.node("t0", "proc", "TTL₀ = min{32, 64,\n128, 255}, TTL₀ ≥ TTL", x2, y2[4])
    c.node("h", "proc", "hops = TTL₀ − TTL", x2, y2[5])
    c.node("r200", "proc", "Ответ = 200:\nTTL, TTL₀, hops", x2, y2[6])
    c.node("o2", "io", "Вывод ответа", x2, y2[7])
    c.node("e2", "term", "Конец", x2, y2[8])
    c.node("n2", "proc", "Ответ = 404:\n«нет данных»", x2 + XR, y2[3])
    chain(c, ["s2", "in2", "get", "d3"])
    c.edge("d3", "t0", label="да")
    chain(c, ["t0", "h", "r200", "o2", "e2"])
    c.edge("d3", "n2", src="right", dst="left", label="нет")
    merge_back(c, "n2", above(y2[7]), x_main=x2)
    c.node("la", "proc", "а)", -1, 3.2)
    c.node("lb", "proc", "б)", x2 - 1, 3.2)
    for k in ("la", "lb"):
        c.nodes[k]["kind"] = "label"
    _render_with_labels(c, OUT / "fig10_ttl_probe.png")


def _render_with_labels(c, path):
    """Подписи «а)», «б)» над частями рисунка — без рамки."""
    draw = c.draw_symbol

    def sym(ax, n):
        if n["kind"] == "label":
            ax.text(n["x"], n["y"], n["text"], fontsize=11, family="Liberation Serif",
                    ha="center", va="center")
        else:
            draw(ax, n)
    c.draw_symbol = sym
    c.render(path)


# ---------------------------------------------------------------- рис. 11: аутентификация
def auth():
    c = Chart(); patch_free_edges(c)
    y = ys(12, {10: 0.6})
    c.node("s", "term", "Начало", 0, y[0])
    c.node("in", "io", "Токен JWT, отпечаток\nсертификата клиента", 0, y[1])
    c.node("d1", "dec", "Подпись HS256\nи издатель верны?", 0, y[2])
    c.node("d2", "dec", "Срок действия\nне истёк?", 0, y[3])
    c.node("d3", "dec", "cnf.x5t#S256 =\nотпечатку?", 0, y[4])
    c.node("db", "pred", "Найти сессию по jti\nв WG_SESSIONS", 0, y[5])
    c.node("d4", "dec", "Сессия есть и\nне отозвана?", 0, y[6])
    c.node("ok", "io", "Ответ 200: sub, role,\njti, сетевой контекст", 0, y[7])
    c.node("e", "term", "Конец", 0, y[10])
    chain(c, ["s", "in", "d1"])
    labels = ["token_invalid", "token_expired", "binding_mismatch", "session_revoked"]
    for i, (d, lab) in enumerate(zip(["d1", "d2", "d3", "d4"], labels)):
        c.node(f"r{i}", "proc", f"Причина отказа:\n{lab}", XR, c.nodes[d]["y"])
        c.edge(d, f"r{i}", src="right", dst="left", label="нет")
        c.node(f"c{i}", "conn", "1", XR + W / 2 + 1.6, c.nodes[d]["y"])
        c.edge(f"r{i}", f"c{i}", src="right", dst="left")
    c.edge("d1", "d2", label="да")
    c.edge("d2", "d3", label="да")
    c.edge("d3", "db", label="да")
    c.edge("db", "d4")
    c.edge("d4", "ok", label="да")
    c.node("ci", "conn", "1", -XR, y[7])
    c.node("au", "proc", "Событие\nAUTH_FAILURE в аудит", -XR, y[8])
    c.node("o401", "io", "Ответ 401 с причиной", -XR, y[9])
    c.edge("ci", "au")
    c.edge("au", "o401")
    ym = above(y[10])
    c.edges.append(dict(a="o401", b=None, src="bottom", dst=None,
                        via=[(-XR, ym), (0, ym)], label=None, label_at=None,
                        arrow=True, free=True))
    c.edge("ok", "e")
    c.render(OUT / "fig11_auth.png")


# ---------------------------------------------------------------- рис. 12: безопасность
def security():
    c = Chart(); patch_free_edges(c)
    y = ys(13, {5: 0.6, 6: 1.0, 8: 0.6, 11: 1.0})
    c.node("s", "term", "Начало", 0, y[0])
    c.node("in", "io", "Телеметрия, hops,\nэталоны из реестра", 0, y[1])
    c.node("init", "proc", "score = 0;\nиндикаторы = { }", 0, y[2])
    c.node("d1", "dec", "ТД в реестре,\nSSID совпадает?", 0, y[3])
    c.node("d2", "dec", "PMF требуется\nи не согласован?", 0, y[4])
    c.node("d3", "dec", "|hops − эталон|\n> допуска?", 0, y[5])
    c.node("tw", "pred", "Поиск двойников\nв списке видимых\nсетей (find_twins)", 0, y[6])
    c.node("d4", "dec", "Двойники\nнайдены?", 0, y[7])
    c.node("d5", "dec", "score ≥ 0,8?", 0, y[8])
    c.node("d6", "dec", "score ≥ 0,4?", 0, y[9])
    c.node("al", "proc", "Вердикт ALLOW", 0, y[10])
    c.node("out", "io", "Вердикт, score,\nиндикаторы, сценарий", 0, y[11])
    c.node("e", "term", "Конец", 0, y[12])
    c.node("k1", "proc", "K1: ТД не доверена;\nscore = score + 1,0", XR, y[3])
    c.node("k2", "proc", "K2: нет PMF;\nscore = score + 1,0", XR, y[4])
    c.node("n1", "proc", "N1: отклонение hops;\nscore = score + 0,4", XR, y[5])
    c.node("n2", "proc", "N2: двойник в эфире;\nscore = score + 0,4", XR, y[7])
    c.node("bl", "proc", "Вердикт BLOCK", XR, y[8])
    c.node("su", "proc", "Вердикт SUSPICIOUS", XR, y[9])
    chain(c, ["s", "in", "init", "d1"])
    c.edge("d1", "d2", label="да")
    c.edge("d2", "d3", label="нет")
    c.edge("d3", "tw", label="нет")
    c.edge("tw", "d4")
    c.edge("d4", "d5", label="нет")
    c.edge("d5", "d6", label="нет")
    c.edge("d6", "al", label="нет")
    chain(c, ["al", "out", "e"])
    c.edge("d1", "k1", src="right", dst="left", label="нет")
    c.edge("d2", "k2", src="right", dst="left", label="да")
    c.edge("d3", "n1", src="right", dst="left", label="да")
    c.edge("d4", "n2", src="right", dst="left", label="да")
    c.edge("d5", "bl", src="right", dst="left", label="да")
    c.edge("d6", "su", src="right", dst="left", label="да")
    merge_back(c, "k2", above(y[5]))
    merge_back(c, "n1", above(y[6], 0))
    merge_back(c, "n2", above(y[8]))
    # K1 пропускает проверки K2 и N1: обход по правой вертикали
    yk = above(y[6], 1)
    c.edges.append(dict(a="k1", b=None, src="right", dst=None,
                        via=[(LANE, y[3]), (LANE, yk), (0, yk)], label=None,
                        label_at=None, arrow=True, free=True))
    ysu = above(y[11], 1)
    yb = above(y[11], 0)
    merge_back(c, "su", ysu)
    c.edges.append(dict(a="bl", b=None, src="right", dst=None,
                        via=[(LANE, y[8]), (LANE, yb), (0, yb)], label=None,
                        label_at=None, arrow=True, free=True))
    c.render(OUT / "fig12_security.png")


# ---------------------------------------------------------------- рис. 13: реестр
def registry():
    c = Chart(); patch_free_edges(c)
    y = ys(10, {8: 0.6, 9: 0.6})
    c.node("s", "term", "Начало", 0, y[0])
    c.node("in", "io", "Запрос POST /aps,\nзаголовок X-Admin-Key", 0, y[1])
    c.node("d1", "dec", "Ключ\nадминистратора\nверен?", 0, y[2])
    c.node("nm", "proc", "Нормализовать BSSID\nк виду aa:bb:cc:dd:ee:ff", 0, y[3])
    c.node("d2", "dec", "BSSID —\nMAC-адрес?", 0, y[4])
    c.node("f", "pred", "Найти запись ТД\nв WG_TRUSTED_APS", 0, y[5])
    c.node("d3", "dec", "Запись\nсуществует?", 0, y[6])
    c.node("ins", "proc", "Добавить запись ТД\n(active = истина)", 0, y[7])
    c.node("out", "io", "Ответ 201: эталонные\nпараметры ТД", 0, y[8])
    c.node("e", "term", "Конец", 0, y[9])
    c.node("r1", "io", "Ответ 403", XR, y[2])
    c.node("r2", "io", "Ответ 422", XR, y[4])
    c.node("up", "proc", "Обновить эталоны,\nactive = истина", XR, y[6])
    chain(c, ["s", "in", "d1"])
    c.edge("d1", "nm", label="да")
    c.edge("nm", "d2")
    c.edge("d2", "f", label="да")
    c.edge("f", "d3")
    c.edge("d3", "ins", label="нет")
    chain(c, ["ins", "out", "e"])
    c.edge("d1", "r1", src="right", dst="left", label="нет")
    c.edge("d2", "r2", src="right", dst="left", label="нет")
    c.edge("d3", "up", src="right", dst="left", label="да")
    merge_back(c, "up", above(y[8]))
    for i, r in enumerate(["r1", "r2"]):
        c.node(f"c{i}", "conn", "1", XR, c.nodes[r]["y"] - H / 2 - 1.6)
        c.edge(r, f"c{i}")
    c.node("ci", "conn", "1", -XR, above(y[9]))
    c.edges.append(dict(a="ci", b=None, src="right", dst=None,
                        via=[(0, c.nodes["ci"]["y"])], label=None, label_at=None,
                        arrow=True, free=True))
    c.render(OUT / "fig13_registry.png")


# ---------------------------------------------------------------- рис. 14: аудит
def audit():
    c = Chart(); patch_free_edges(c)
    y = ys(10, {3: 0.6, 4: 0.6, 5: 0.6, 7: 0.6})
    c.node("s", "term", "Начало", 0, y[0])
    c.node("in", "io", "Событие JSON от\nмикросервиса", 0, y[1])
    c.node("d1", "dec", "SECURITY_\nVERDICT?", 0, y[2])
    c.node("d2", "dec", "AUTH_FAILURE?", 0, y[3])
    c.node("d3", "dec", "REQUEST_\nCOMPLETED?", 0, y[4])
    c.node("st", "pred", "Записать событие в\nтаблицу\nWG_AUDIT_EVENTS", 0, y[5])
    c.node("d4", "dec", "Важность warning\nили critical?", 0, y[6])
    c.node("out", "io", "Ответ 202", 0, y[7])
    c.node("e", "term", "Конец", 0, y[8])
    c.node("m1", "proc", "wg_verdicts_total +1;\nwg_indicators_total +1;\nscore → wg_risk_score", XR, y[2])
    c.node("m2", "proc", "wg_auth_failures_total\n{reason} +1", XR, y[3])
    c.node("m3", "proc", "wg_gateway_requests_total\n+1; задержка →\nwg_gateway_latency", XR, y[4])
    c.node("lg", "proc", "Вывести событие в\nжурнал контейнера", XR, y[6])
    chain(c, ["s", "in", "d1"])
    c.edge("d1", "d2", label="нет")
    c.edge("d2", "d3", label="нет")
    c.edge("d3", "st", label="нет")
    c.edge("st", "d4")
    c.edge("d4", "out", label="нет")
    c.edge("out", "e")
    for d, m in (("d1", "m1"), ("d2", "m2"), ("d3", "m3"), ("d4", "lg")):
        c.edge(d, m, src="right", dst="left", label="да")
        nxt = {"d1": "d2", "d2": "d3", "d3": "st", "d4": "out"}[d]
        merge_back(c, m, above(c.nodes[nxt]["y"]))
    c.render(OUT / "fig14_audit.png")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for f in (gateway, ttl_probe, auth, security, registry, audit):
        f()
    print("ok")
