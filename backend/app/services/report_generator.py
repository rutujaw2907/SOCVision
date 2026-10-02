import json
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def _parse_iocs(iocs):
    if not iocs:
        return []

    if isinstance(iocs, list):
        return [str(item) for item in iocs]

    if isinstance(iocs, dict):
        return [
            f"{key}: {value}"
            for key, value in iocs.items()
        ]

    if isinstance(iocs, str):
        try:
            parsed = json.loads(iocs)

            if isinstance(parsed, list):
                return [str(item) for item in parsed]

            if isinstance(parsed, dict):
                return [
                    f"{key}: {value}"
                    for key, value in parsed.items()
                ]

            return [iocs]

        except json.JSONDecodeError:
            return [iocs]

    return []


def _safe(value):
    if value is None:
        return "—"

    return str(value)


def generate_incident_report(
    incident,
    ai_analysis=None,
):
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"SOCVision Incident Report #{incident.id}",
        author="SOCVision",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        alignment=TA_CENTER,
        spaceAfter=6,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.grey,
        alignment=TA_CENTER,
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=14,
        spaceAfter=6,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
    )

    story = []

    story.append(
        Paragraph(
            "SOCVision",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Security Operations Center Incident Report",
            subtitle_style,
        )
    )

    # Incident overview
    story.append(
        Paragraph(
            "1. Incident Overview",
            heading_style,
        )
    )

    overview_data = [
        [
            "Incident ID",
            _safe(incident.id),
            "Attack",
            _safe(incident.attack),
        ],
        [
            "Severity",
            _safe(incident.severity),
            "Risk Score",
            f"{_safe(incident.risk_score)}/100",
        ],
        [
            "Source IP",
            _safe(incident.ip),
            "Workflow Status",
            _safe(
                incident.incident_status
                or "OPEN"
            ),
        ],
        [
            "HTTP Method",
            _safe(incident.method),
            "HTTP Status",
            _safe(incident.status),
        ],
        [
            "Endpoint",
            _safe(incident.path),
            "Timestamp",
            _safe(incident.timestamp),
        ],
    ]

    overview_table = Table(
        overview_data,
        colWidths=[
            30 * mm,
            55 * mm,
            35 * mm,
            55 * mm,
        ],
    )

    overview_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#eeeeee"),
            ),
            (
                "BACKGROUND",
                (2, 0),
                (2, -1),
                colors.HexColor("#eeeeee"),
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#cccccc"),
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Helvetica",
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold",
            ),
            (
                "FONTNAME",
                (2, 0),
                (2, -1),
                "Helvetica-Bold",
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP",
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6,
            ),
        ])
    )

    story.append(
        overview_table
    )

    # MITRE
    story.append(
        Paragraph(
            "2. MITRE ATT&CK",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Technique:</b> "
            f"{_safe(incident.mitre_technique)}",
            body_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Technique Name:</b> "
            f"{_safe(incident.mitre_name)}",
            body_style,
        )
    )

    # IOCs
    story.append(
        Paragraph(
            "3. Indicators of Compromise",
            heading_style,
        )
    )

    iocs = _parse_iocs(
        incident.iocs
    )

    if iocs:
        for ioc in iocs:
            story.append(
                Paragraph(
                    f"• {_safe(ioc)}",
                    small_style,
                )
            )
    else:
        story.append(
            Paragraph(
                "No indicators of compromise were recorded.",
                body_style,
            )
        )

    # Risk
    story.append(
        Paragraph(
            "4. Risk Assessment",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            f"The SOCVision detection engine assigned "
            f"a risk score of "
            f"<b>{_safe(incident.risk_score)}/100</b> "
            f"with severity "
            f"<b>{_safe(incident.severity)}</b>.",
            body_style,
        )
    )

    # AI analysis
    story.append(
        Paragraph(
            "5. AI Security Analyst",
            heading_style,
        )
    )

    if ai_analysis:
        for block in ai_analysis.split(
            "\n\n"
        ):
            clean_block = (
                block.strip()
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\n", "<br/>")
            )

            if clean_block:
                story.append(
                    Paragraph(
                        clean_block,
                        body_style,
                    )
                )
    else:
        story.append(
            Paragraph(
                "No AI analyst report was generated for this incident.",
                body_style,
            )
        )

    # Footer information
    story.append(
        Spacer(
            1,
            10,
        )
    )

    story.append(
        Paragraph(
            "Generated by SOCVision Security Operations Platform",
            subtitle_style,
        )
    )

    document.build(
        story
    )

    buffer.seek(0)

    return buffer