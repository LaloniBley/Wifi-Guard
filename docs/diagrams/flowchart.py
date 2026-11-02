"""Мини-движок построения блок-схем по ГОСТ 19.701-90 (ИСО 5807-85).

Символы: терминатор, процесс, предопределённый процесс, решение,
данные (ввод-вывод), подготовка, соединитель, граница цикла.
Все символы одного размера (п. 4.1.3), линии подходят к символу сверху
или слева и выходят снизу или справа (п. 4.2.4). Для наглядности стрелки
ставятся на всех линиях потока (п. 4.2.1 допускает стрелки для ясности).
"""
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.patches import Circle, Polygon, Rectangle  # noqa: E402

W, H = 7.0, 2.4        # размер символа (ширина ≈ 2,7 высоты)
LW = 0.9
FONT = "Liberation Serif"
FS = 9.0               # кегль на рисунке в натуральную величину, пт


class Chart:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.labels = []

    def node(self, nid, kind, text, x, y, ident=None):
        self.nodes[nid] = dict(kind=kind, text=text, x=x, y=y, ident=ident)
        return nid

    def edge(self, a, b, src="bottom", dst="top", via=(), label=None, label_at=None,
             arrow=None):
        self.edges.append(dict(a=a, b=b, src=src, dst=dst, via=list(via), label=label,
                               label_at=label_at, arrow=arrow))

    # точки подключения
    def port(self, nid, side):
        n = self.nodes[nid]
        x, y = n["x"], n["y"]
        w = 1.6 if n["kind"] == "conn" else W
        h = 1.6 if n["kind"] == "conn" else H
        return {"top": (x, y + h / 2), "bottom": (x, y - h / 2),
                "left": (x - w / 2, y), "right": (x + w / 2, y)}[side]

    def draw_symbol(self, ax, n):
        x, y, kind = n["x"], n["y"], n["kind"]
        x0, y0 = x - W / 2, y - H / 2
        style = dict(fill=False, lw=LW, ec="black")
        if kind == "proc":
            ax.add_patch(Rectangle((x0, y0), W, H, **style))
        elif kind == "pred":
            ax.add_patch(Rectangle((x0, y0), W, H, **style))
            d = 0.35
            ax.plot([x0 + d, x0 + d], [y0, y0 + H], color="black", lw=LW)
            ax.plot([x0 + W - d, x0 + W - d], [y0, y0 + H], color="black", lw=LW)
        elif kind == "term":
            t = np.linspace(-np.pi / 2, np.pi / 2, 40)
            r = H / 2
            right = [(x + W / 2 - r + r * np.cos(a), y + r * np.sin(a)) for a in t]
            left = [(x - W / 2 + r - r * np.cos(a), y - r * np.sin(a)) for a in t]
            ax.add_patch(Polygon(right + left, closed=True, **style))
        elif kind == "dec":
            ax.add_patch(Polygon([(x, y0), (x + W / 2, y), (x, y0 + H), (x - W / 2, y)],
                                 closed=True, **style))
        elif kind == "io":
            s = 0.6
            ax.add_patch(Polygon([(x0 + s, y0 + H), (x0 + W, y0 + H), (x0 + W - s, y0), (x0, y0)],
                                 closed=True, **style))
        elif kind == "prep":
            s = 0.7
            ax.add_patch(Polygon([(x0 + s, y0 + H), (x0 + W - s, y0 + H), (x0 + W, y),
                                  (x0 + W - s, y0), (x0 + s, y0), (x0, y)], closed=True, **style))
        elif kind == "loop_start":
            s = 0.6
            ax.add_patch(Polygon([(x0 + s, y0 + H), (x0 + W - s, y0 + H), (x0 + W, y0 + H - s),
                                  (x0 + W, y0), (x0, y0), (x0, y0 + H - s)], closed=True, **style))
        elif kind == "loop_end":
            s = 0.6
            ax.add_patch(Polygon([(x0, y0 + H), (x0 + W, y0 + H), (x0 + W, y0 + s),
                                  (x0 + W - s, y0), (x0 + s, y0), (x0, y0 + s)], closed=True, **style))
        elif kind == "conn":
            ax.add_patch(Circle((x, y), 0.8, **style))
        fs = FS if kind != "dec" else FS - 0.5
        ax.text(x, y, n["text"], ha="center", va="center", fontsize=fs, family=FONT,
                linespacing=1.15)
        if n.get("ident"):
            ax.text(x0, y0 + H + 0.12, n["ident"], ha="left", va="bottom", fontsize=FS - 1.5,
                    family=FONT)

    def draw_edge(self, ax, e):
        p0 = self.port(e["a"], e["src"])
        p1 = self.port(e["b"], e["dst"])
        pts = [p0] + e["via"] + [p1]
        # если промежуточных точек нет — ортогональная трасса по умолчанию
        if not e["via"] and p0[0] != p1[0] and p0[1] != p1[1]:
            if e["src"] in ("left", "right"):
                pts = [p0, (p1[0], p0[1]), p1]
            else:
                ym = p0[1] - 0.8
                pts = [p0, (p0[0], ym), (p1[0], ym), p1]
        xs, ys = zip(*pts)
        ax.plot(xs, ys, color="black", lw=LW, solid_capstyle="butt")
        if e["arrow"] is not False:
            (ax0, ay0), (bx, by) = pts[-2], pts[-1]
            length = max(abs(bx - ax0), abs(by - ay0))
            k = min(0.45, length) / length
            start = (bx - (bx - ax0) * k, by - (by - ay0) * k)
            ax.annotate("", xy=(bx, by), xytext=start,
                        arrowprops=dict(arrowstyle="-|>", color="black", lw=LW,
                                        mutation_scale=9, shrinkA=0, shrinkB=0))
        if e["label"]:
            if e["label_at"]:
                lx, ly = e["label_at"]
            else:
                a, b = pts[0], pts[1]
                if e["src"] == "bottom":
                    ax.text(a[0] - 0.25, a[1] - 0.45, e["label"], fontsize=FS - 0.5,
                            family=FONT, ha="right", va="center")
                    return
                elif e["src"] == "right":
                    lx, ly = a[0] + 0.25, a[1] + 0.25
                else:
                    lx, ly = a[0] - 0.9, a[1] + 0.25
            ax.text(lx, ly, e["label"], fontsize=FS - 0.5, family=FONT, ha="left", va="center")

    def render(self, path, margin=0.6):
        xs = [n["x"] for n in self.nodes.values()]
        ys = [n["y"] for n in self.nodes.values()]
        vx = [p[0] for e in self.edges for p in e["via"]]
        vy = [p[1] for e in self.edges for p in e["via"]]
        xmin = min(xs + vx) - W / 2 - margin
        xmax = max(xs + vx) + W / 2 + margin
        ymin = min(ys + vy) - H / 2 - margin
        ymax = max(ys + vy) + H / 2 + margin
        # масштаб: рисунок помещается на страницу (≤16 × 23 см) без уменьшения
        wu, hu = xmax - xmin, ymax - ymin
        cm = min(16.0 / wu, 23.0 / hu, 0.6)       # см на единицу координат
        fig = plt.figure(figsize=(wu * cm / 2.54, hu * cm / 2.54))
        ax = fig.add_axes([0, 0, 1, 1])
        ax.set_xlim(xmin, xmax)
        ax.set_ylim(ymin, ymax)
        ax.set_aspect("equal")
        global FS
        FS = 9.0 * min(1.0, cm / 0.53)   # кегль уменьшается только для очень крупных схем
        ax.axis("off")
        for e in self.edges:
            self.draw_edge(ax, e)
        for n in self.nodes.values():
            self.draw_symbol(ax, n)
        fig.savefig(path, dpi=300, facecolor="white")
        plt.close(fig)
