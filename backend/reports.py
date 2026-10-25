import hashlib
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

def make_report(scan: dict) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        name="HeaderTitle",
        parent=styles["Title"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        alignment=0
    )
    subtitle_style = ParagraphStyle(
        name="SubTitle",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#475569")
    )
    section_title = ParagraphStyle(
        name="SectionHeader",
        parent=styles["Heading2"],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0369a1"),
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        name="TableBody",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b")
    )
    warning_style = ParagraphStyle(
        name="WarningText",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#b91c1c")
    )
    safe_style = ParagraphStyle(
        name="SafeText",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#15803d")
    )

    story = []

    # 1. Header with Cyber Classification Badge
    header_data = [
        [
            Paragraph("<b>SCAMSHIELD ENTERPRISE · THREAT INTELLIGENCE DOSSIER</b>", title_style),
            Paragraph(f"<b>CLASSIFICATION:</b> OFFICIAL AUDIT<br/><b>HASH:</b> {scan.get('report_hash', 'N/A')}", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[120 * mm, 62 * mm])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, -1), "RIGHT")
    ]))
    story.append(header_table)
    story.append(Spacer(1, 3 * mm))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

    # 2. Executive Summary Box
    score = scan.get("score", 0)
    classification = scan.get("classification", "Unknown")
    risk_color = colors.HexColor("#dc2626") if score >= 60 else colors.HexColor("#d97706") if score >= 30 else colors.HexColor("#16a34a")

    summary_rows = [
        ["Target URL", Paragraph(f"<b>{scan.get('url', '')}</b>", body_style)],
        ["Domain Host", Paragraph(f"<b>{scan.get('domain', '')}</b>", body_style)],
        ["Scanned At", scan.get("scanned_at", "")],
        ["Audit Dossier ID", f"#{scan.get('id', 'N/A')}"],
        ["Threat Level", Paragraph(f"<font color='{risk_color.hexval()}'><b>{classification.upper()} ({score}/100)</b></font>", body_style)],
        ["Threat Feed Status", scan.get("threat_status", "clean").title()],
        ["Brand Protection", scan.get("brand_detected") or "No Impersonation Detected"]
    ]
    summary_table = Table(summary_rows, colWidths=[40 * mm, 142 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 5 * mm))

    # 3. Multi-Engine AI & Technical Telemetry
    story.append(Paragraph("<b>1. Multi-Engine AI & Telemetry Matrix</b>", section_title))
    ai_rows = [
        ["Engine / Verification Layer", "Detection Status", "Confidence / Details"],
        ["Scikit-Learn ML Ensemble", scan.get("ml_prediction", "N/A").title(), f"{scan.get('ml_probability', 0.0)}% Phishing Probability"],
        ["PyTorch Deep Learning (Char-CNN)", "Active" if scan.get("dl_score", 0) > 0 else "Benign", f"{scan.get('dl_score', 0.0)}% Neural Phishing Score"],
        ["Domain Age (WHOIS)", f"{scan.get('domain_age_days')} days" if scan.get('domain_age_days') is not None else "Unknown / Private", "Risk if < 30 days old"],
        ["HTTPS & TLS Handshake", "Verified" if scan.get("http_status") else "Checked", scan.get("https_certificate", "N/A")],
        ["HTTP Response Code", str(scan.get("http_status") or "Unreachable / Blocked"), "Standard Status Code"]
    ]
    ai_table = Table(ai_rows, colWidths=[55 * mm, 45 * mm, 82 * mm])
    ai_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0369a1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(ai_table)
    story.append(Spacer(1, 5 * mm))

    # 4. Forensic Signals & Explainable AI
    story.append(Paragraph("<b>2. Forensic Warning Signals & Explainable AI Factors</b>", section_title))
    signals = scan.get("signals", [])
    if not signals:
        story.append(Paragraph("No anomalous risk signals recorded for this domain.", body_style))
    else:
        for s in signals:
            is_risk = s.get("risk", False)
            icon = "<b>[CRITICAL RISK]</b>" if is_risk else "<b>[VERIFIED SAFE]</b>"
            txt = str(s.get("text", "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            para = Paragraph(f"{icon} {txt}", warning_style if is_risk else safe_style)
            story.append(para)
            story.append(Spacer(1, 1.5 * mm))

    story.append(Spacer(1, 4 * mm))

    # 5. Security & Incident Response Recommendation
    story.append(Paragraph("<b>3. Cyber Safety & Incident Response Recommendation</b>", section_title))
    rec = (
        "<b>IMMEDIATE ACTION REQUIRED:</b> DO NOT SUBMIT PASSWORDS, CREDIT CARDS, OR PERSONAL DATA. This website displays malicious indicators including brand spoofing or suspicious machine learning classifications. If credentials were submitted, change corresponding passwords immediately and alert your security team."
        if score >= 60 else
        "<b>CAUTION:</b> Domain exhibits elevated risk signals. Verify the spelling of the URL, check official company contact channels, and refrain from making payments until authenticity is confirmed."
        if score >= 30 else
        "<b>CLEAR:</b> No automated threat indicators matched. Normal online vigilance is recommended."
    )
    story.append(Paragraph(rec, body_style))
    story.append(Spacer(1, 6 * mm))

    # Footer notice
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=5))
    story.append(Paragraph("Generated by ScamShield Enterprise Autonomous Defense Platform · Automated Research Intelligence", subtitle_style))

    doc.build(story)
    return buf.getvalue()
