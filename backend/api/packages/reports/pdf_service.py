import os
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

REPORTS_DIR = os.getenv(
    "REPORTS_DIR", "/tmp/shieldsentinel/reports"
)


def generate_pdf_report(
    scan, findings: list, output_path: str
) -> str:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer,
        Table, TableStyle, PageBreak,
        HRFlowable,
    )
    from reportlab.lib.styles import (
        getSampleStyleSheet, ParagraphStyle,
    )
    from reportlab.lib.enums import (
        TA_CENTER, TA_LEFT,
    )
    from reportlab.lib.colors import HexColor

    INDIGO   = HexColor("#6366f1")
    WHITE    = HexColor("#ffffff")
    GRAY     = HexColor("#9ca3af")
    RED      = HexColor("#ef4444")
    ORANGE   = HexColor("#f97316")
    YELLOW   = HexColor("#eab308")
    GREEN    = HexColor("#22c55e")
    DARK_BG  = HexColor("#f8fafc")
    RED_BG   = HexColor("#fef2f2")
    ORANGE_BG= HexColor("#fff7ed")
    YELLOW_BG= HexColor("#fefce8")
    GREEN_BG = HexColor("#f0fdf4")

    os.makedirs(REPORTS_DIR, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    # ── Styles ─────────────────────────────────
    styles = getSampleStyleSheet()
    S = {
        "title": ParagraphStyle(
            "title", fontSize=28,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER, spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontSize=13,
            fontName="Helvetica",
            alignment=TA_CENTER, spaceAfter=16,
            textColor=GRAY,
        ),
        "section": ParagraphStyle(
            "section", fontSize=15,
            fontName="Helvetica-Bold",
            textColor=INDIGO,
            spaceBefore=14, spaceAfter=4,
        ),
        "finding_h": ParagraphStyle(
            "finding_h", fontSize=11,
            fontName="Helvetica-Bold",
            spaceBefore=8, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body", fontSize=10,
            fontName="Helvetica",
            leading=14, spaceAfter=5,
        ),
        "small": ParagraphStyle(
            "small", fontSize=9,
            fontName="Helvetica",
            leading=13,
            textColor=HexColor("#374151"),
            spaceAfter=4,
        ),
        "mono": ParagraphStyle(
            "mono", fontSize=8,
            fontName="Courier",
            leading=12, spaceAfter=4,
            backColor=HexColor("#f1f5f9"),
        ),
        "tip": ParagraphStyle(
            "tip", fontSize=10,
            fontName="Helvetica-Oblique",
            textColor=HexColor("#166534"),
            spaceAfter=5, leftIndent=8,
        ),
        "risk": ParagraphStyle(
            "risk", fontSize=32,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "conf": ParagraphStyle(
            "conf", fontSize=9,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
            textColor=RED,
        ),
    }

    def hr():
        return HRFlowable(
            width="100%", thickness=0.5,
            color=HexColor("#e5e7eb"),
            spaceAfter=4,
        )

    def hr_color(c):
        return HRFlowable(
            width="100%", thickness=1,
            color=c, spaceAfter=4,
        )

    story = []

    # ── Cover page ──────────────────────────────
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph(
        "ShieldSentinel", S["title"]
    ))
    story.append(Paragraph(
        "SECURITY ASSESSMENT REPORT",
        S["subtitle"],
    ))
    story.append(hr_color(INDIGO))
    story.append(Spacer(1, 0.8*cm))

    details = [
        ["Target:",     scan.target],
        ["Scan Type:",  scan.scan_type.upper()],
        ["Date:",
            scan.created_at.strftime(
                "%B %d, %Y %H:%M UTC"
            )],
        ["Duration:",
            _fmt_duration(
                scan.duration_seconds or 0
            )],
        ["Intensity:",
            (scan.intensity or "standard").upper()],
        ["Risk Score:",
            f"{scan.risk_score or 'N/A'}/100 "
            f"({scan.risk_grade or 'N/A'})"],
    ]
    tbl = Table(
        details, colWidths=[4*cm, 13*cm]
    )
    tbl.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (-1, -1),
         "Helvetica"),
        ("FONTSIZE",  (0, 0), (-1, -1), 10),
        ("FONTNAME",  (0, 0), (0, -1),
         "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), INDIGO),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 1*cm))

    score = scan.risk_score or 0
    risk_color = (
        RED if score < 31 else
        ORANGE if score < 61 else
        YELLOW if score < 81 else
        GREEN
    )
    story.append(Paragraph(
        f"<font color='#{risk_color.hexval()}'>"
        f"Risk Score: {score}/100"
        f"</font>",
        S["risk"],
    ))

    story.append(Spacer(1, 2*cm))
    story.append(Paragraph(
        "CONFIDENTIAL — For authorized use only",
        S["conf"],
    ))
    story.append(PageBreak())

    # ── Executive summary ───────────────────────
    story.append(Paragraph(
        "Executive Summary", S["section"]
    ))
    story.append(hr_color(INDIGO))

    attacked = [
        f for f in findings
        if f.get("attack_worked")
    ]
    defended = [
        f for f in findings
        if not f.get("attack_worked") and
        f.get("was_attempted")
    ]
    critical_count = sum(
        1 for f in attacked
        if f.get("severity") == "critical"
    )
    high_count = sum(
        1 for f in attacked
        if f.get("severity") == "high"
    )
    medium_count = sum(
        1 for f in attacked
        if f.get("severity") == "medium"
    )

    summary_text = _generate_exec_summary(
        scan, attacked, critical_count,
        high_count, medium_count,
    )
    story.append(Paragraph(summary_text, S["body"]))
    story.append(Spacer(1, 0.4*cm))

    stats_data = [
        ["Severity", "Count", "Recommended Action"],
        ["Critical", str(critical_count),
         "Fix immediately — within 24 hours"],
        ["High", str(high_count),
         "Fix within 7 days"],
        ["Medium", str(medium_count),
         "Fix within 30 days"],
        ["Low",
         str(sum(1 for f in attacked
                 if f.get("severity") == "low")),
         "Fix in next release"],
        ["Protected",
         str(len(defended)),
         "No vulnerability found"],
    ]
    st = Table(
        stats_data,
        colWidths=[4*cm, 3*cm, 10*cm],
    )
    st.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), INDIGO),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),
         "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("BACKGROUND",    (0, 1), (-1, 1), RED_BG),
        ("BACKGROUND",    (0, 2), (-1, 2), ORANGE_BG),
        ("BACKGROUND",    (0, 3), (-1, 3), YELLOW_BG),
        ("BACKGROUND",    (0, 5), (-1, 5), GREEN_BG),
        ("GRID",          (0, 0), (-1, -1),
         0.5, HexColor("#e5e7eb")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
    ]))
    story.append(st)
    story.append(PageBreak())

    # ── Findings ────────────────────────────────
    story.append(Paragraph(
        "Vulnerability Findings", S["section"]
    ))
    story.append(hr_color(INDIGO))

    SEV_COLORS = {
        "critical": (RED,    RED_BG),
        "high":     (ORANGE, ORANGE_BG),
        "medium":   (YELLOW, YELLOW_BG),
        "low":      (HexColor("#3b82f6"),
                     HexColor("#eff6ff")),
    }

    sorted_findings = sorted(
        attacked,
        key=lambda f: {
            "critical": 0, "high": 1,
            "medium": 2, "low": 3,
        }.get(f.get("severity", "low"), 4),
    )

    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "low")
        sev_color, sev_bg = SEV_COLORS.get(
            sev, (GRAY, DARK_BG)
        )

        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            f"#{i} [{sev.upper()}] "
            f"{f.get('vuln_type', 'Unknown')}",
            S["finding_h"],
        ))

        location = (
            f.get("url") or
            (f"{f.get('file_path')}:"
             f"{f.get('line_number')}"
             if f.get("file_path") else "—")
        )

        detail_rows = [
            ["Location:", location[:60]],
            ["OWASP:",
             f.get("owasp_category", "—")],
            ["Tool:",
             f.get("tool_source", "—")],
        ]
        if f.get("cvss_score"):
            detail_rows.append([
                "CVSS:",
                str(f["cvss_score"]),
            ])
        if f.get("money_loss_min"):
            detail_rows.append([
                "Est. Loss:",
                f"${f['money_loss_min']:,} – "
                f"${f['money_loss_max']:,}",
            ])

        dt = Table(
            detail_rows,
            colWidths=[3*cm, 14*cm],
        )
        dt.setStyle(TableStyle([
            ("FONTNAME",  (0, 0), (0, -1),
             "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 0), (0, -1), INDIGO),
            ("BACKGROUND",(0, 0), (-1, -1), sev_bg),
            ("BOTTOMPADDING", (0,0),(-1,-1), 3),
        ]))
        story.append(dt)

        if f.get("description"):
            story.append(Paragraph(
                f.get("description", "")[:400],
                S["small"],
            ))

        ai = f.get("ai_fix")
        if ai and isinstance(ai, dict):
            if ai.get("ai_suggestion"):
                story.append(Paragraph(
                    f"Fix: {ai['ai_suggestion']}",
                    S["tip"],
                ))
            if ai.get("defense_examples"):
                for ex in ai["defense_examples"][:1]:
                    if ex.get("code_after"):
                        story.append(Paragraph(
                            f"Secure code: "
                            f"{ex['code_after'][:120]}",
                            S["mono"],
                        ))

        story.append(hr())

    # ── Protected attacks ───────────────────────
    story.append(PageBreak())
    story.append(Paragraph(
        "Attack Resistance Verification",
        S["section"],
    ))
    story.append(hr_color(GREEN))
    story.append(Paragraph(
        "The following attack types were tested "
        "and no vulnerabilities were found.",
        S["body"],
    ))
    story.append(Spacer(1, 0.3*cm))

    if defended:
        def_data = [["Attack Type", "Status"]]
        for d in defended:
            def_data.append([
                d.get("vuln_type", ""),
                "Protected",
            ])
        dt = Table(
            def_data,
            colWidths=[12*cm, 5*cm],
        )
        dt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), GREEN),
            ("TEXTCOLOR",  (0, 0), (-1, 0), WHITE),
            ("FONTNAME",   (0, 0), (-1, 0),
             "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [WHITE, GREEN_BG]),
            ("GRID",       (0, 0), (-1, -1),
             0.5, HexColor("#e5e7eb")),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ]))
        story.append(dt)

    def _header_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GRAY)
        canvas.drawString(
            2*cm, 1*cm,
            "ShieldSentinel Security Report — "
            "CONFIDENTIAL",
        )
        canvas.drawRightString(
            A4[0] - 2*cm, 1*cm,
            f"Page {doc.page}",
        )
        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=_header_footer,
        onLaterPages=_header_footer,
    )
    return output_path


def _generate_exec_summary(
    scan, attacked, critical, high, medium
) -> str:
    try:
        from packages.ai.llm_router import LLMRouter
        top = [
            f.get("vuln_type", "")
            for f in attacked
            if f.get("severity") in
            ["critical", "high"]
        ][:5]
        prompt = (
            f"Write a 3-paragraph executive summary "
            f"for a security report.\n"
            f"Target: {scan.target}\n"
            f"Risk Score: {scan.risk_score}/100\n"
            f"Critical: {critical}, "
            f"High: {high}, Medium: {medium}\n"
            f"Top issues: "
            f"{', '.join(top) or 'none'}\n\n"
            f"Para 1: Overall security posture.\n"
            f"Para 2: Most critical findings and "
            f"their business impact.\n"
            f"Para 3: Recommended immediate actions.\n"
            f"Plain text only. No markdown."
        )
        return LLMRouter().chat(
            [{"role": "user", "content": prompt}],
            max_tokens=400,
        )
    except Exception:
        return (
            f"Security assessment completed for "
            f"{scan.target}. "
            f"Risk score: {scan.risk_score or 'N/A'}"
            f"/100. "
            f"{critical} critical and {high} high "
            f"severity vulnerabilities were found "
            f"requiring immediate attention. "
            f"Remediation should begin with critical "
            f"findings within 24 hours."
        )


def _fmt_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"
