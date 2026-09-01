import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import logging

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak

from aegis.scanners.models import SASTScanResult, Severity, VulnerabilityFinding

logger = logging.getLogger("aegis.pdf_generator")

class PDFReportGenerator:
    """
    Generates a professional Enterprise-grade PDF report from scan results.
    """

    def __init__(self, output_path: str):
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='AegisTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor("#2c3e50"),
            alignment=1 # Center
        ))
        self.styles.add(ParagraphStyle(
            name='AegisSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.HexColor("#34495e")
        ))
        self.styles.add(ParagraphStyle(
            name='VulnTitle',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=10,
            textColor=colors.HexColor("#c0392b")
        ))
        self.styles.add(ParagraphStyle(
            name='NormalText',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=10
        ))
        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Code'],
            fontSize=9,
            backColor=colors.HexColor("#f4f6f7"),
            borderPadding=5,
            spaceAfter=10
        ))

    def generate(self, scan_result: SASTScanResult, repo_name: str, dast_screenshots: Optional[List[str]] = None) -> bool:
        try:
            doc = SimpleDocTemplate(self.output_path, pagesize=A4,
                                    rightMargin=40, leftMargin=40,
                                    topMargin=40, bottomMargin=40)
            story = []

            # Header
            story.append(Paragraph("🛡️ Aegis Engine Security Report", self.styles['AegisTitle']))
            story.append(Paragraph(f"Repository: {repo_name}", self.styles['AegisSubtitle']))
            story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['NormalText']))
            story.append(Spacer(1, 20))

            # Summary Table
            story.append(Paragraph("Executive Summary", self.styles['AegisSubtitle']))
            
            crit = scan_result.findings_by_severity.get(Severity.CRITICAL, 0)
            high = scan_result.findings_by_severity.get(Severity.HIGH, 0)
            med = scan_result.findings_by_severity.get(Severity.MEDIUM, 0)
            low = scan_result.findings_by_severity.get(Severity.LOW, 0)
            info = scan_result.findings_by_severity.get(Severity.INFO, 0)

            summary_data = [
                ["Severity", "Count"],
                ["CRITICAL", crit],
                ["HIGH", high],
                ["MEDIUM", med],
                ["LOW / INFO", low + info],
                ["TOTAL", scan_result.total_findings]
            ]

            summary_table = Table(summary_data, colWidths=[200, 100])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#34495e")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#ecf0f1")),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                
                # Colors for severity rows
                ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor("#c0392b")), # Crit
                ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor("#e67e22")), # High
                ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor("#f1c40f")), # Med
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 30))

            # Detailed Findings
            story.append(PageBreak())
            story.append(Paragraph("Detailed Findings", self.styles['AegisSubtitle']))

            if not scan_result.findings:
                story.append(Paragraph("No vulnerabilities detected. Repository is secure.", self.styles['NormalText']))
            else:
                secret_findings = [f for f in scan_result.findings if f.scanner.value == "secret"]
                other_findings = [f for f in scan_result.findings if f.scanner.value != "secret"]
                
                if secret_findings:
                    story.append(Paragraph("🚨 Leaked Secrets / Утечки данных", self.styles['AegisTitle']))
                    story.append(Paragraph("The following hardcoded secrets were discovered in the codebase. These pose an immediate critical risk.", self.styles['NormalText']))
                    story.append(Spacer(1, 10))
                    for idx, finding in enumerate(secret_findings, 1):
                        self._add_finding_to_story(story, finding, idx)
                        
                if other_findings:
                    if secret_findings:
                        story.append(PageBreak())
                        story.append(Paragraph("Other Vulnerabilities", self.styles['AegisSubtitle']))
                    for idx, finding in enumerate(other_findings, 1):
                        self._add_finding_to_story(story, finding, idx)

            # Append DAST Proofs if any
            if dast_screenshots:
                story.append(PageBreak())
                story.append(Paragraph("Proof of Concept (DAST)", self.styles['AegisSubtitle']))
                story.append(Paragraph("The following screenshots were automatically generated by Aegis Engine during dynamic exploitation.", self.styles['NormalText']))
                story.append(Spacer(1, 20))
                
                for img_path in dast_screenshots:
                    if os.path.exists(img_path):
                        try:
                            # Resize image to fit A4 width
                            img = Image(img_path)
                            img.drawWidth = 500
                            img.drawHeight = img.drawWidth * (img.imageHeight / img.imageWidth)
                            story.append(img)
                            story.append(Spacer(1, 20))
                        except Exception as e:
                            logger.error(f"Failed to embed image {img_path}: {e}")

            doc.build(story)
            return True

        except Exception as e:
            logger.exception(f"PDF generation failed: {e}")
            return False

    def _add_finding_to_story(self, story, finding, idx):
        # Title
        title_text = f"{idx}. [{finding.severity.value}] {finding.title}"
        story.append(Paragraph(title_text, self.styles['VulnTitle']))
        
        # Metadata Table
        meta_data = [
            ["Scanner", finding.scanner.value],
            ["File", f"{finding.file_path} (Line {finding.line_start or 1})"],
        ]
        if finding.cwe:
            meta_data.append(["CWE", ", ".join(finding.cwe)])
        if finding.cve:
            meta_data.append(["CVE", ", ".join(finding.cve)])
            
        t = Table(meta_data, colWidths=[100, 400])
        t.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))
        
        # Description
        story.append(Paragraph("Description:", self.styles['Heading4']))
        story.append(Paragraph(finding.description.replace('\n', '<br/>'), self.styles['NormalText']))
        
        # Recommendation
        if finding.recommendation:
            story.append(Paragraph("Recommendation:", self.styles['Heading4']))
            story.append(Paragraph(finding.recommendation.replace('\n', '<br/>'), self.styles['NormalText']))
        
        # Code Snippet
        if finding.code_snippet:
            snippet = finding.code_snippet[:500] + ("..." if len(finding.code_snippet) > 500 else "")
            # Escape XML characters for reportlab paragraph
            snippet = snippet.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")
            story.append(Spacer(1, 10))
            story.append(Paragraph(snippet, self.styles['CodeBlock']))
            
        story.append(Spacer(1, 20))

