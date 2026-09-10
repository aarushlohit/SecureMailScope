"""
SecureMailScope - Deterministic PDF Report Generator (ReportLab)
"""
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from securemailscope.evidence.ledger import EvidenceLedger


class PDFReporter:
    """
    Renders a formal, publication-ready PDF forensic report
    using ReportLab.
    """

    @staticmethod
    def generate_report(investigation_id: str, ledger: EvidenceLedger, output_path: Path) -> Path:
        inv = ledger.get_investigation(investigation_id)
        if not inv:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        evidence = ledger.get_evidence_for_investigation(investigation_id)
        findings = ledger.get_findings_for_investigation(investigation_id)
        hypotheses = ledger.get_hypotheses_for_investigation(investigation_id)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(str(output_path), pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        story = []

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#0F172A'), spaceAfter=4)
        subtitle_style = ParagraphStyle('SubTitleStyle', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#64748B'), spaceAfter=12)
        h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#1E293B'), spaceBefore=14, spaceAfter=6)
        body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#334155'), leading=12)
        bold_body = ParagraphStyle('BoldBody', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#0F172A'), fontName='Helvetica-Bold')

        # Header
        story.append(Paragraph("SecureMailScope Forensic Investigation Report", title_style))
        story.append(Paragraph("SIH26159 | National Technical Research Organisation (NTRO)", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0EA5E9'), spaceAfter=14))

        # Metadata Table
        posture_score = f"{inv.posture.overall_posture_score}/100" if inv.posture else "N/A"
        risk_lvl = inv.posture.risk_level if inv.posture else "PENDING"
        meta_data = [
            [Paragraph("Investigation ID", bold_body), Paragraph(inv.investigation_id, body_style),
             Paragraph("Security Posture", bold_body), Paragraph(f"<b>{posture_score} ({risk_lvl})</b>", body_style)],
            [Paragraph("PCAP Artifact", bold_body), Paragraph(inv.artifact_name, body_style),
             Paragraph("Completeness", bold_body), Paragraph(f"{inv.completeness_percentage}%", body_style)],
            [Paragraph("SHA-256", bold_body), Paragraph(f"{inv.artifact_sha256[:28]}...", body_style),
             Paragraph("Generated", bold_body), Paragraph(inv.created_at[:19], body_style)]
        ]
        meta_table = Table(meta_data, colWidths=[100, 180, 90, 170])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 14))

        # Findings Section
        story.append(Paragraph("Verified Forensic Findings", h2_style))
        if findings:
            for f in findings:
                f_data = [
                    [Paragraph(f"<b>{f.title}</b> [{f.severity.value.upper()}]", bold_body)],
                    [Paragraph(f"{f.description}", body_style)],
                    [Paragraph(f"<b>Remediation:</b> {f.remediation or 'N/A'}", body_style)],
                    [Paragraph(f"<b>Supporting Evidence:</b> {', '.join(f.evidence_ids)}", body_style)]
                ]
                ftable = Table(f_data, colWidths=[540])
                bg_color = colors.HexColor('#FEF2F2') if f.severity.value == 'critical' else (
                    colors.HexColor('#FFF7ED') if f.severity.value == 'high' else colors.HexColor('#F8FAFC')
                )
                ftable.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), bg_color),
                    ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
                    ('PADDING', (0,0), (-1,-1), 6),
                ]))
                story.append(ftable)
                story.append(Spacer(1, 8))
        else:
            story.append(Paragraph("No cryptographic vulnerabilities observed.", body_style))

        # Evidence Ledger Section
        story.append(Spacer(1, 10))
        story.append(Paragraph("Evidence Ledger Excerpt", h2_style))
        ev_rows = [[Paragraph("ID", bold_body), Paragraph("Type", bold_body), Paragraph("Observed Claim", bold_body), Paragraph("Source", bold_body)]]
        for e in evidence[:10]:
            ev_rows.append([
                Paragraph(e.evidence_id, body_style),
                Paragraph(e.type.value, body_style),
                Paragraph(e.claim[:60] + "...", body_style),
                Paragraph(e.source_tool, body_style)
            ])
        ev_table = Table(ev_rows, colWidths=[65, 120, 265, 90])
        ev_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(ev_table)

        # Build document
        doc.build(story)
        return output_path
