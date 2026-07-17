from html import escape
from pathlib import Path

from docx import Document
from docx.table import Table as DocxTable
from docx.text.paragraph import Paragraph as DocxParagraph
from docx.oxml.ns import qn
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[2]
DOCX_PATH = ROOT / "artifacts" / "agent-demo-guide" / "Sentinell_AI_Agent_Demo_Guide.docx"
PDF_PATH = ROOT / "deliverables" / "Sentinell_AI_Agent_Testing_and_Response_Blur_Guide.pdf"

INK = colors.HexColor("#1C2434")
SLATE = colors.HexColor("#2D3748")
MUTED = colors.HexColor("#667085")
BLUE = colors.HexColor("#2563A6")
LINE = colors.HexColor("#D8E1E8")


def iter_blocks(document):
    body = document.element.body
    for child in body.iterchildren():
        if child.tag == qn("w:p"):
            yield DocxParagraph(child, document)
        elif child.tag == qn("w:tbl"):
            yield DocxTable(child, document)


def page_break_in(paragraph):
    return bool(paragraph._p.xpath(".//w:br[@w:type='page']"))


def paragraph_fill(paragraph):
    shd = paragraph._p.find("./w:pPr/w:shd", paragraph._p.nsmap)
    return shd.get(qn("w:fill")) if shd is not None else None


def paragraph_left_border(paragraph):
    left = paragraph._p.find("./w:pPr/w:pBdr/w:left", paragraph._p.nsmap)
    return left.get(qn("w:color")) if left is not None else None


def cell_fill(cell):
    shd = cell._tc.find("./w:tcPr/w:shd", cell._tc.nsmap)
    return shd.get(qn("w:fill")) if shd is not None else "FFFFFF"


def run_html(run):
    text = escape(run.text).replace("\n", "<br/>")
    if not text:
        return ""
    if run.bold:
        text = f"<b>{text}</b>"
    if run.italic:
        text = f"<i>{text}</i>"
    return text


def paragraph_html(paragraph):
    if paragraph.runs:
        return "".join(run_html(run) for run in paragraph.runs)
    return escape(paragraph.text).replace("\n", "<br/>")


def build_styles():
    base = getSampleStyleSheet()
    return {
        "body": ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=10.2,
            leading=13.2,
            textColor=INK,
            spaceAfter=6,
        ),
        "h1": ParagraphStyle(
            "H1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=19,
            textColor=INK,
            spaceBefore=12,
            spaceAfter=8,
            keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=BLUE,
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True,
        ),
        "h3": ParagraphStyle(
            "H3",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=14,
            textColor=SLATE,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True,
        ),
        "cover_brand": ParagraphStyle(
            "CoverBrand",
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=BLUE,
            spaceBefore=54,
            spaceAfter=8,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle",
            fontName="Helvetica-Bold",
            fontSize=27,
            leading=31,
            textColor=INK,
            spaceAfter=10,
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle",
            fontName="Helvetica",
            fontSize=13,
            leading=17,
            textColor=SLATE,
            spaceAfter=18,
        ),
        "box": ParagraphStyle(
            "Box",
            fontName="Helvetica",
            fontSize=9.6,
            leading=12.2,
            textColor=INK,
        ),
        "detail": ParagraphStyle(
            "Detail",
            fontName="Helvetica",
            fontSize=9.1,
            leading=11.8,
            leftIndent=12,
            textColor=INK,
            spaceAfter=3,
        ),
        "bullet": ParagraphStyle(
            "Bullet",
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            leftIndent=16,
            firstLineIndent=-9,
            textColor=INK,
            spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "Small",
            fontName="Helvetica",
            fontSize=8.7,
            leading=11,
            textColor=INK,
        ),
    }


def boxed_paragraph(paragraph, styles):
    fill = paragraph_fill(paragraph) or "F8F9FA"
    accent = paragraph_left_border(paragraph) or "D8E1E8"
    content = Paragraph(paragraph_html(paragraph), styles["box"])
    box = Table([[content]], colWidths=[6.18 * inch])
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(f"#{fill}")),
                ("BOX", (0, 0), (-1, -1), 0.35, LINE),
                ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(f"#{accent}")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return box


def paragraph_flowable(paragraph, styles, index):
    text = paragraph_html(paragraph)
    style_name = paragraph.style.name if paragraph.style else "Normal"

    if index == 0:
        return Paragraph(text, styles["cover_brand"])
    if index == 1:
        return Paragraph(text, styles["cover_title"])
    if index == 2:
        return Paragraph(text, styles["cover_subtitle"])
    if style_name == "Heading 1":
        return Paragraph(text, styles["h1"])
    if style_name == "Heading 2":
        return Paragraph(text, styles["h2"])
    if style_name == "Heading 3":
        return Paragraph(text, styles["h3"])
    if style_name.startswith("List Bullet"):
        return Paragraph(f"&#8226;&nbsp;&nbsp;{text}", styles["bullet"])
    if style_name == "List Number":
        return Paragraph(text, styles["bullet"], bulletText="1.")
    if paragraph_fill(paragraph):
        return boxed_paragraph(paragraph, styles)
    if text.strip():
        use_style = styles["detail"] if text.startswith(("Expected:", "Why:", "Say to the panel:")) else styles["body"]
        return Paragraph(text, use_style)
    return Spacer(1, 4)


def docx_table_flowable(table, styles):
    rows = []
    fills = []
    for r_idx, row in enumerate(table.rows):
        row_data = []
        row_fills = []
        for cell in row.cells:
            text = "<br/>".join(escape(p.text) for p in cell.paragraphs if p.text)
            row_data.append(Paragraph(text, styles["small"]))
            row_fills.append(cell_fill(cell))
        rows.append(row_data)
        fills.append(row_fills)

    if not rows:
        return Spacer(1, 1)

    cols = len(rows[0])
    if cols == 2:
        widths = [1.45 * inch, 4.73 * inch]
    elif cols == 3:
        widths = [1.25 * inch, 2.65 * inch, 2.28 * inch]
    else:
        widths = [6.18 * inch / cols] * cols

    pdf_table = Table(rows, colWidths=widths, repeatRows=1 if len(rows) > 4 else 0)
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    for r_idx, row in enumerate(fills):
        for c_idx, fill in enumerate(row):
            commands.append(("BACKGROUND", (c_idx, r_idx), (c_idx, r_idx), colors.HexColor(f"#{fill}")))
    pdf_table.setStyle(TableStyle(commands))
    return pdf_table


def on_page(canvas, doc):
    page_num = canvas.getPageNumber()
    if page_num > 1:
        canvas.saveState()
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.4)
        canvas.line(72, 748, 540, 748)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(72, 756, "SENTINELL.AI  |  AGENT DEMONSTRATION GUIDE")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(540, 38, f"Panel-ready test script  |  Page {page_num}")
        canvas.restoreState()


def build_pdf():
    source = Document(DOCX_PATH)
    styles = build_styles()
    raw_blocks = list(iter_blocks(source))
    story = []
    paragraph_index = 0
    idx = 0

    while idx < len(raw_blocks):
        block = raw_blocks[idx]
        if isinstance(block, DocxParagraph):
            if page_break_in(block):
                story.append(PageBreak())
                idx += 1
                continue

            flow = paragraph_flowable(block, styles, paragraph_index)
            paragraph_index += 1

            if paragraph_fill(block) and idx + 3 < len(raw_blocks):
                next_blocks = raw_blocks[idx + 1:idx + 4]
                next_text = [b.text for b in next_blocks if isinstance(b, DocxParagraph)]
                if len(next_text) == 3 and next_text[0].startswith("Expected:") and next_text[1].startswith("Why:") and next_text[2].startswith("Say to the panel:"):
                    grouped = [flow]
                    for detail in next_blocks:
                        grouped.append(paragraph_flowable(detail, styles, paragraph_index))
                        paragraph_index += 1
                    story.append(KeepTogether(grouped))
                    idx += 4
                    continue

            story.append(flow)
        else:
            story.append(docx_table_flowable(block, styles))
            story.append(Spacer(1, 8))
        idx += 1

    PDF_PATH.parent.mkdir(parents=True, exist_ok=True)
    pdf = SimpleDocTemplate(
        str(PDF_PATH),
        pagesize=letter,
        rightMargin=1 * inch,
        leftMargin=1 * inch,
        topMargin=0.72 * inch,
        bottomMargin=0.65 * inch,
        title="Sentinell.AI Agent Testing and Response-Blur Demo Guide",
        author="Sentinell.AI Project Team",
        subject="Panel-ready prompts for all security agents and response monitoring",
    )
    pdf.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(PDF_PATH)


if __name__ == "__main__":
    build_pdf()
