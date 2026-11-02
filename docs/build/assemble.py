"""Вставка главы 3, источников 28–30, приложений и пунктов содержания в docx."""
import json
import re
import shutil
import sys
from pathlib import Path

from PIL import Image

import chapter3
from ooxml import ref_item, toc_entry

UN = Path(sys.argv[1])              # распакованный docx
FIGS = Path(sys.argv[2])            # каталог с PNG рисунков
PAGES = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
EMU_PER_CM = 360000

doc_path = UN / "word/document.xml"
rels_path = UN / "word/_rels/document.xml.rels"
doc = doc_path.read_text(encoding="utf8")
rels = rels_path.read_text(encoding="utf8")

next_rid = max(int(n) for n in re.findall(r'Id="rId(\d+)"', rels)) + 1
pic_id = 900


def fig(name, number, caption, width_cm=None):
    global next_rid, pic_id
    src = FIGS / f"{name}.png"
    target = f"media/wg_{name}.png"
    shutil.copy(src, UN / "word" / target)
    rid = f"rId{next_rid}"
    next_rid += 1
    pic_id += 1
    global rels
    rels = rels.replace("</Relationships>",
                        f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/'
                        f'2006/relationships/image" Target="{target}"/></Relationships>')
    im = Image.open(src)
    dpi = im.info.get("dpi", (300, 300))[0] or 300
    w_cm = im.size[0] / dpi * 2.54
    h_cm = im.size[1] / dpi * 2.54
    if width_cm:
        h_cm, w_cm = h_cm * width_cm / w_cm, width_cm
    if w_cm > 16.0:
        h_cm, w_cm = h_cm * 16.0 / w_cm, 16.0
    from ooxml import figure
    return figure(rid, int(w_cm * EMU_PER_CM), int(h_cm * EMU_PER_CM), pic_id,
                  f"Рисунок {number} – {caption}")


body = chapter3.build(fig)
apps, app_toc = chapter3.appendices()


def paras(xml):
    return list(re.finditer(r'<w:p[ >].*?</w:p>', xml, flags=re.S))


def find_para(pattern):
    for m in paras(doc):
        txt = "".join(re.findall(r'<w:t[^>]*>([^<]*)</w:t>', m.group(0)))
        if re.search(pattern, txt):
            return m
    raise KeyError(pattern)


# 1) глава 3 — после разрыва страницы в конце главы 2, перед списком литературы
m = find_para(r"^Таким образом, диаграммы 6-8")
after = doc[m.end():]
pb = re.search(r'<w:p[ >](?:(?!</w:p>).)*?<w:br w:type="page"/>.*?</w:p>', after, flags=re.S)
pos = m.end() + pb.end()
doc = doc[:pos] + body + chapter3.page_break() + doc[pos:]

# 2) источники 28–30 — после последнего пункта списка
refs = [
    "Microservice Security Metrics for Secure Communication, Identity Management, and "
    "Observability / U. Zdun, P.-J. Quéval, G. Simhandl [et al.] // ACM Transactions on Software "
    "Engineering and Methodology. – 2023. – Vol. 32, № 1. – P. 1–34. – DOI 10.1145/3532183.",
    "Миронова В. Г. Модель поверхности атак для сложных систем на основе микросервисной "
    "архитектуры // Известия Юго-Западного государственного университета. – 2025. – Т. 29, № 1. – "
    "С. 96–106. – DOI 10.21869/2223-1560-2025-29-1-96-106.",
    "Rujichaikul P., Rassameeroj I. Token-Based Authentication Monitoring System // Journal of "
    "Cyber Security and Mobility. – 2025. – Vol. 14, № 4. – P. 777–798. – "
    "DOI 10.13052/jcsm2245-1439.1441.",
]
m = find_para(r"^Пахомов М\. А\., Соболев")
doc = doc[:m.end()] + "".join(ref_item(r) for r in refs) + doc[m.end():]

# 3) приложения — в конец тела документа, перед sectPr
sect = doc.rindex("<w:sectPr")
doc = doc[:sect] + apps + doc[sect:]

# 4) содержание
m = find_para(r"^2\.2\. UML-диаграммы\d*$")
toc3 = (toc_entry("ГЛАВА 3. РАЗРАБОТКА МИКРОСЕРВИСОВ", "_Toc_ch3", PAGES.get("_Toc_ch3", "")) +
        toc_entry("3.1. Описание микросервисов и их функций", "_Toc_ch3_1", PAGES.get("_Toc_ch3_1", "")) +
        toc_entry("3.2. Развертывание микросервисов", "_Toc_ch3_2", PAGES.get("_Toc_ch3_2", "")))
doc = doc[:m.end()] + toc3 + doc[m.end():]
m = find_para(r"^СПИСОК ИСПОЛЬЗУЕМЫХ ИСТОЧНИКОВ И ЛИТЕРАТУРЫ\d+$")
toc_app = "".join(toc_entry(title, bm, PAGES.get(bm, ""), style="11") for title, bm in app_toc)
doc = doc[:m.end()] + toc_app + doc[m.end():]
if "_Toc_refs" in PAGES:   # номер страницы списка литературы сдвигается
    doc = re.sub(r'(PAGEREF _Toc242019308 \\h </w:instrText><w:fldChar w:fldCharType="separate"/><w:t>)\d+',
                 lambda mm: mm.group(1) + PAGES["_Toc_refs"], doc)

doc_path.write_text(doc, encoding="utf8")
rels_path.write_text(rels, encoding="utf8")
print("ok", next_rid, pic_id)
