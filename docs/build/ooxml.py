"""Генерация фрагментов WordprocessingML в стиле курсовой (ГОСТ 7.32-2017)."""
from xml.sax.saxutils import escape

BODY_PPR = ('<w:pPr><w:spacing w:line="360" w:lineRule="auto"/><w:ind w:firstLine="709"/>'
            '<w:jc w:val="both"/></w:pPr>')


def t(text):
    return f'<w:t xml:space="preserve">{escape(text)}</w:t>'


def runs(text, rpr=""):
    """Текст с разметкой: `код` — моноширинный, остальное — обычный."""
    out = []
    parts = text.split("`")
    for i, part in enumerate(parts):
        if not part:
            continue
        if i % 2 == 1:
            out.append(f'<w:r><w:rPr><w:rFonts w:ascii="Courier New" w:hAnsi="Courier New" '
                       f'w:cs="Courier New"/>{rpr}<w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr>{t(part)}</w:r>')
        else:
            out.append(f'<w:r>{"<w:rPr>"+rpr+"</w:rPr>" if rpr else ""}{t(part)}</w:r>')
    return "".join(out)


def para(text):
    return f'<w:p>{BODY_PPR}{runs(text)}</w:p>'


def dash_item(text):
    return para("– " + text)


def chapter(text, bm_id, bm_name):
    return ('<w:p><w:pPr><w:pStyle w:val="a6"/><w:spacing w:before="0" w:after="240"/>'
            '<w:contextualSpacing w:val="0"/></w:pPr>'
            f'<w:bookmarkStart w:id="{bm_id}" w:name="{bm_name}"/><w:r>{t(text)}</w:r>'
            f'<w:bookmarkEnd w:id="{bm_id}"/></w:p>')


def section(num, text, bm_id, bm_name, before=240):
    return (f'<w:p><w:pPr><w:pStyle w:val="a6"/><w:spacing w:before="{before}" w:after="240"/>'
            '<w:jc w:val="both"/><w:rPr><w:caps w:val="0"/></w:rPr></w:pPr>'
            f'<w:bookmarkStart w:id="{bm_id}" w:name="{bm_name}"/><w:r>{t(num + " " + text[0])}</w:r>'
            f'<w:r><w:rPr><w:caps w:val="0"/></w:rPr>{t(text[1:])}</w:r>'
            f'<w:bookmarkEnd w:id="{bm_id}"/></w:p>')


def heading1(text, bm_id, bm_name, sub=None):
    """Заголовок уровня 1 (как «СПИСОК ИСПОЛЬЗУЕМЫХ ИСТОЧНИКОВ»), для приложений."""
    xml = ('<w:p><w:pPr><w:pStyle w:val="1"/><w:spacing w:line="360" w:lineRule="auto"/>'
           '<w:rPr><w:b w:val="0"/><w:bCs w:val="0"/></w:rPr></w:pPr>'
           f'<w:bookmarkStart w:id="{bm_id}" w:name="{bm_name}"/><w:r>{t(text)}</w:r>')
    if sub:
        xml += f'<w:r><w:br/></w:r><w:r><w:rPr><w:caps w:val="0"/></w:rPr>{t(sub)}</w:r>'
    return xml + f'<w:bookmarkEnd w:id="{bm_id}"/></w:p>'


def page_break():
    return '<w:p><w:pPr><w:spacing w:after="0"/></w:pPr><w:r><w:br w:type="page"/></w:r></w:p>'


def figure(rid, cx_emu, cy_emu, pic_id, caption):
    drawing = (
        f'<w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0">'
        f'<wp:extent cx="{cx_emu}" cy="{cy_emu}"/><wp:effectExtent l="0" t="0" r="0" b="0"/>'
        f'<wp:docPr id="{pic_id}" name="Рисунок {pic_id}"/>'
        '<wp:cNvGraphicFramePr><a:graphicFrameLocks xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" noChangeAspect="1"/></wp:cNvGraphicFramePr>'
        '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        f'<pic:nvPicPr><pic:cNvPr id="{pic_id}" name="fig{pic_id}.png"/><pic:cNvPicPr/></pic:nvPicPr>'
        f'<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
        f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx_emu}" cy="{cy_emu}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>'
        '</a:graphicData></a:graphic></wp:inline></w:drawing>')
    img = ('<w:p><w:pPr><w:keepNext/><w:spacing w:before="120" w:line="240" w:lineRule="auto"/>'
           f'<w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:noProof/></w:rPr>{drawing}</w:r></w:p>')
    cap = ('<w:p><w:pPr><w:spacing w:after="120" w:line="360" w:lineRule="auto"/><w:jc w:val="center"/>'
           '<w:rPr><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:pPr>'
           f'<w:r><w:rPr><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr>{t(caption)}</w:r></w:p>')
    return img + cap


def listing(caption, code, size=18):
    """Подпись листинга над кодом и код моноширинным шрифтом (по строке на абзац)."""
    xml = ('<w:p><w:pPr><w:keepNext/><w:spacing w:before="120" w:after="60" w:line="360" '
           'w:lineRule="auto"/><w:jc w:val="left"/></w:pPr>'
           f'<w:r><w:rPr><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr>{t(caption)}</w:r></w:p>')
    lines = code.rstrip("\n").split("\n")
    for i, line in enumerate(lines):
        last = i == len(lines) - 1
        keep = "" if last or len(lines) > 40 else "<w:keepNext/>"
        border = ""
        xml += (f'<w:p><w:pPr>{keep}<w:keepLines/>{border}<w:spacing w:after="{120 if last else 0}" '
                'w:line="240" w:lineRule="auto"/><w:ind w:left="284"/><w:jc w:val="left"/></w:pPr>'
                '<w:r><w:rPr><w:rFonts w:ascii="Courier New" w:hAnsi="Courier New" w:cs="Courier New"/>'
                f'<w:noProof/><w:sz w:val="{size}"/><w:szCs w:val="{size}"/></w:rPr>{t(line if line else " ")}</w:r></w:p>')
    return xml


def table(caption, header, rows, widths):
    """Таблица по ГОСТ 7.32: «Таблица N – Название» над таблицей слева."""
    total = sum(widths)
    cap = ('<w:p><w:pPr><w:keepNext/><w:spacing w:before="120" w:after="60" w:line="360" '
           'w:lineRule="auto"/><w:jc w:val="left"/></w:pPr>'
           f'<w:r>{t(caption)}</w:r></w:p>')
    b = '<w:{0} w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
    borders = "".join(b.format(x) for x in ("top", "left", "bottom", "right", "insideH", "insideV"))
    xml = (f'<w:tbl><w:tblPr><w:tblW w:w="{total}" w:type="dxa"/><w:jc w:val="center"/>'
           f'<w:tblBorders>{borders}</w:tblBorders><w:tblLayout w:type="fixed"/>'
           '<w:tblCellMar><w:left w:w="85" w:type="dxa"/><w:right w:w="85" w:type="dxa"/></w:tblCellMar>'
           '<w:tblLook w:val="04A0"/></w:tblPr><w:tblGrid>'
           + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + '</w:tblGrid>')

    def row(cells, head=False):
        r = '<w:tr>' + ('<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>' if head else '<w:trPr><w:cantSplit/></w:trPr>')
        for c, w in zip(cells, widths):
            jc = "center" if head else "left"
            r += (f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/></w:tcPr>'
                  f'<w:p><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/><w:jc w:val="{jc}"/></w:pPr>'
                  + runs(c, '<w:sz w:val="24"/><w:szCs w:val="24"/>').replace('<w:sz w:val="26"/><w:szCs w:val="26"/>', '<w:sz w:val="22"/><w:szCs w:val="22"/>')
                  + '</w:p></w:tc>')
        return r + '</w:tr>'
    xml += row(header, True) + "".join(row(r) for r in rows) + '</w:tbl>'
    after = '<w:p><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr></w:p>'
    return cap + xml + after


def toc_entry(text, anchor, page, style="23"):
    return (f'<w:p><w:pPr><w:pStyle w:val="{style}"/><w:tabs><w:tab w:val="right" w:leader="dot" w:pos="9062"/></w:tabs>'
            '<w:rPr><w:noProof/></w:rPr></w:pPr>'
            f'<w:hyperlink w:anchor="{anchor}" w:history="1"><w:r><w:rPr><w:rStyle w:val="a9"/><w:noProof/></w:rPr>{t(text)}</w:r>'
            '<w:r><w:rPr><w:noProof/><w:webHidden/></w:rPr><w:tab/><w:fldChar w:fldCharType="begin"/>'
            f'<w:instrText xml:space="preserve"> PAGEREF {anchor} \\h </w:instrText><w:fldChar w:fldCharType="separate"/>'
            f'<w:t>{page}</w:t><w:fldChar w:fldCharType="end"/></w:r></w:hyperlink></w:p>')


def ref_item(text):
    """Пункт списка литературы (нумерованный список numId=4, как в документе)."""
    return ('<w:p><w:pPr><w:pStyle w:val="ae"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="4"/></w:numPr>'
            '<w:spacing w:line="360" w:lineRule="auto"/><w:ind w:left="0" w:firstLine="709"/><w:jc w:val="both"/></w:pPr>'
            f'<w:r>{t(text)}</w:r></w:p>')
