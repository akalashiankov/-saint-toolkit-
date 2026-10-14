import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from datetime import datetime

def generate_pdf_report(target_name, target_url, auth_ref, authorized_by, alerts, filename="reports/security_assessment_report.pdf"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    styles = getSampleStyleSheet()

    # Custom Color Palette
    primary_color = colors.HexColor("#1A365D")   # Deep Navy
    text_dark = colors.HexColor("#2D3748")       # Charcoal
    border_color = colors.HexColor("#E2E8F0")    # Light Grey

    # Risk level colors for badges/text
    risk_colors = {
        "High": colors.HexColor("#E53E3E"),          # Red
        "Critical": colors.HexColor("#9B2C2C"),      # Dark Red
        "Medium": colors.HexColor("#DD6B20"),        # Amber
        "Low": colors.HexColor("#3182CE"),           # Sky Blue
        "Informational": colors.HexColor("#718096"), # Grey
        "Info": colors.HexColor("#718096")
    }

    # Severity ordering rank for sorting: Critical (1) to Informational (5)
    severity_order = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
        "Informational": 5,
        "Info": 5
    }

    # Sort alerts by severity rank
    if alerts:
        alerts = sorted(alerts, key=lambda x: severity_order.get(x.get('risk', 'Informational'), 99))

    # Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=primary_color,
        spaceAfter=4,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor("#4A5568"),
        spaceAfter=15
    )

    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=primary_color,
        spaceBefore=15,
        spaceAfter=8,
        fontName='Helvetica-Bold'
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontSize=10,
        textColor=text_dark,
        leading=14
    )

    cell_style = ParagraphStyle('Cell', parent=styles['Normal'], fontSize=9, textColor=text_dark, leading=12)
    cell_header = ParagraphStyle('CellHeader', parent=styles['Normal'], fontSize=9, textColor=colors.white, fontName='Helvetica-Bold', leading=12)

    # 1. Header Section
    story.append(Paragraph("SAINT SECURITY ASSESSMENT REPORT", title_style))
    story.append(Paragraph(f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=primary_color, spaceAfter=15))

    # Metadata Table
    meta_data = [
        [Paragraph("<b>Target Name:</b>", cell_style), Paragraph(target_name, cell_style)],
        [Paragraph("<b>Target URL:</b>", cell_style), Paragraph(target_url, cell_style)],
        [Paragraph("<b>Authorized By:</b>", cell_style), Paragraph(authorized_by, cell_style)],
        [Paragraph("<b>Authorization Ref:</b>", cell_style), Paragraph(auth_ref, cell_style)]
    ]
    meta_table = Table(meta_data, colWidths=[120, 410])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F7FAFC")),
        ('BOX', (0,0), (-1,-1), 0.5, border_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # 2. Executive Summary
    story.append(Paragraph("Executive Summary", section_heading))
    exec_summary_text = (
        f"An automated web application security assessment was performed against <b>{target_url}</b> "
        f"pursuant to authorization reference <b>{auth_ref}</b>. The assessment utilized the SAINT security "
        f"scanning toolkit powered by OWASP ZAP core engines to discover potential vulnerabilities, review security "
        f"headers, and evaluate exposure levels."
    )
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 15))

    # 3. Vulnerability Findings Summary Table
    story.append(Paragraph("Vulnerability Findings Summary", section_heading))
    
    table_data = [[
        Paragraph("Risk Level", cell_header),
        Paragraph("Vulnerability / Alert Name", cell_header),
        Paragraph("Instances", cell_header)
    ]]

    if not alerts:
        table_data.append([
            Paragraph("Info", cell_style),
            Paragraph("No vulnerabilities returned or scan completed cleanly.", cell_style),
            Paragraph("0", cell_style)
        ])
    else:
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            name = alert.get('name', 'Unknown Alert')
            count = str(len(alert.get('instances', []))) if 'instances' in alert else "1"
            
            # Apply color tagging for risk level
            color_obj = risk_colors.get(risk, colors.HexColor("#718096"))
            color_hex = color_obj.hexval() if hasattr(color_obj, 'hexval') else "#718096"
            risk_styled = Paragraph(f"<font color='{color_hex}'><b>{risk}</b></font>", cell_style)
            
            table_data.append([risk_styled, Paragraph(name, cell_style), Paragraph(count, cell_style)])

    findings_table = Table(table_data, colWidths=[90, 360, 60])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_color),
        ('BOX', (0,0), (-1,-1), 0.5, border_color),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 15))

    # 4. Detailed Findings, Recommendations & References Section
    story.append(Paragraph("Vulnerability Details, Recommendations & References", section_heading))
    
    if not alerts:
        story.append(Paragraph("The target scan returned a clean bill of health with no active security findings reported.", body_style))
    else:
        for alert in alerts:
            name = alert.get('name', 'Unknown Alert')
            risk = alert.get('risk', 'Informational')
            description = alert.get('description', 'No detailed description provided.')
            solution = alert.get('solution', 'Review configuration and apply vendor hardening guidelines.')
            reference = alert.get('reference', 'No references provided.')
            
            color_obj = risk_colors.get(risk, colors.HexColor("#718096"))
            color_hex = color_obj.hexval() if hasattr(color_obj, 'hexval') else "#718096"
            
            detail_content = [
                Paragraph(f"<b>{name}</b> (<font color='{color_hex}'><b>{risk} Risk</b></font>)", ParagraphStyle('SubHead', parent=styles['Normal'], fontSize=10, fontName='Helvetica-Bold', textColor=primary_color)),
                Spacer(1, 4),
                Paragraph(f"<b>Description:</b> {description}", body_style),
                Spacer(1, 4),
                Paragraph(f"<b>Recommendation / Remediation:</b> {solution}", body_style),
                Spacer(1, 4),
                Paragraph(f"<b>References:</b> {reference}", body_style),
                Spacer(1, 10)
            ]
            story.append(Table([[detail_content]], colWidths=[510], style=[
                ('BOX', (0,0), (-1,-1), 0.5, border_color),
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#FAFAFA")),
                ('PADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(Spacer(1, 8))

    doc.build(story)

if __name__ == "__main__":
    pass
