"""
PDF report generator for SentinelShield AI Security Platform
Creates professional compliance and security reports in PDF format
"""

import os
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from enum import Enum
import logging

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus.tableofcontents import TableOfContents
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("ReportLab not available - PDF generation disabled")

from app.compliance.owasp_reporter import OWASPComplianceReport, ComplianceStatus

logger = logging.getLogger(__name__)


class ReportType(str, Enum):
    """Types of PDF reports"""
    OWASP_COMPLIANCE = "owasp_compliance"
    SECURITY_ASSESSMENT = "security_assessment"
    INCIDENT_SUMMARY = "incident_summary"
    EXECUTIVE_DASHBOARD = "executive_dashboard"


class PDFGenerator:
    """PDF report generator"""
    
    def __init__(self):
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
        
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        logger.info("PDF generator initialized")
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#2C3E50'),
            alignment=TA_CENTER,
            borderWidth=0,
            borderColor=colors.transparent
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#34495E'),
            alignment=TA_LEFT
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            textColor=HexColor('#2980B9'),
            alignment=TA_LEFT,
            borderWidth=0,
            borderColor=colors.transparent
        ))
        
        # Body text style
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            textColor=HexColor('#2C3E50'),
            alignment=TA_LEFT
        ))
        
        # Status style
        self.styles.add(ParagraphStyle(
            name='StatusText',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=4,
            alignment=TA_CENTER,
            borderWidth=1,
            borderColor=colors.transparent,
            borderRadius=5
        ))
    
    def generate_owasp_compliance_report(self, report: OWASPComplianceReport,
                                        output_path: str = None) -> str:
        """Generate OWASP compliance PDF report"""
        if output_path is None:
            output_path = f"owasp_compliance_{report.report_id}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Build story (content)
        story = []
        
        # Title page
        story.extend(self._create_title_page(report))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(report))
        story.append(Spacer(1, 20))
        
        # Overall assessment
        story.extend(self._create_overall_assessment(report))
        story.append(Spacer(1, 20))
        
        # Category assessments
        story.extend(self._create_category_assessments(report))
        story.append(Spacer(1, 20))
        
        # Statistics
        story.extend(self._create_statistics_section(report))
        story.append(Spacer(1, 20))
        
        # Priority actions
        story.extend(self._create_priority_actions(report))
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
        
        logger.info(f"OWASP compliance PDF report generated: {output_path}")
        return output_path
    
    def _create_title_page(self, report: OWASPComplianceReport) -> List:
        """Create title page"""
        elements = []
        
        # Main title
        elements.append(Paragraph("SentinelShield AI Security Platform", self.styles['CustomTitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Report title
        elements.append(Paragraph("OWASP LLM Top 10 Compliance Report", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Report metadata
        metadata_data = [
            ['Report ID:', report.report_id],
            ['Generated:', report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Assessment Period:', f"{report.period_start.strftime('%Y-%m-%d')} to {report.period_end.strftime('%Y-%m-%d')}"],
            ['Application:', report.application or 'All Applications'],
            ['Overall Score:', f"{report.overall_score:.2f}/1.0"],
            ['Compliance Status:', report.overall_status.value],
            ['Compliant Categories:', f"{report.compliant_categories}/{report.total_categories}"]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#F8F9FA')),
            ('TEXTCOLOR', (0, 0), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#E9ECEF')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ]))
        
        elements.append(metadata_table)
        elements.append(Spacer(1, 1*inch))
        
        # Status indicator
        status_color = self._get_status_color(report.overall_status)
        status_text = f"<font color='{status_color}' size='14'><b>{report.overall_status.value}</b></font>"
        elements.append(Paragraph(status_text, self.styles['StatusText']))
        
        return elements
    
    def _create_executive_summary(self, report: OWASPComplianceReport) -> List:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Summary text
        summary_paragraphs = report.executive_summary.split('\n\n')
        for paragraph in summary_paragraphs:
            if paragraph.strip():
                elements.append(Paragraph(paragraph, self.styles['CustomBody']))
                elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _create_overall_assessment(self, report: OWASPComplianceReport) -> List:
        """Create overall assessment section"""
        elements = []
        
        elements.append(Paragraph("Overall Assessment", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Score visualization
        score_data = [
            ['Metric', 'Value', 'Status'],
            ['Overall Score', f"{report.overall_score:.2f}/1.0", self._get_score_status(report.overall_score)],
            ['Compliant Categories', f"{report.compliant_categories}/{report.total_categories}", report.overall_status.value],
            ['Total Scans', f"{report.total_scans:,}", '-'],
            ['Blocked Attacks', f"{report.blocked_scans:,}", '-'],
            ['Security Incidents', f"{report.incidents}", '-']
        ]
        
        score_table = Table(score_data, colWidths=[2.5*inch, 2*inch, 2*inch])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#3498DB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8F9FA')),
            ('TEXTCOLOR', (0, 1), (-1, -1), black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#DEE2E6'))
        ]))
        
        elements.append(score_table)
        
        return elements
    
    def _create_category_assessments(self, report: OWASPComplianceReport) -> List:
        """Create category assessments section"""
        elements = []
        
        elements.append(Paragraph("OWASP LLM Top 10 Category Assessment", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Category table
        category_data = [['Category', 'Status', 'Score', 'Key Findings']]
        
        for category, assessment in report.category_assessments.items():
            status_color = self._get_status_color(assessment.status)
            status_text = f"<font color='{status_color}'>{assessment.status.value}</font>"
            
            # Truncate findings for table display
            key_finding = assessment.findings[0] if assessment.findings else "No issues"
            if len(key_finding) > 50:
                key_finding = key_finding[:47] + "..."
            
            category_data.append([
                category.value,
                status_text,
                f"{assessment.score:.2f}",
                key_finding
            ])
        
        category_table = Table(category_data, colWidths=[2*inch, 1.5*inch, 1*inch, 2*inch])
        category_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#3498DB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8F9FA')),
            ('TEXTCOLOR', (0, 1), (-1, -1), black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#DEE2E6'))
        ]))
        
        elements.append(category_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Detailed findings for non-compliant categories
        non_compliant = [(cat, ass) for cat, ass in report.category_assessments.items() 
                        if ass.status != ComplianceStatus.COMPLIANT]
        
        if non_compliant:
            elements.append(Paragraph("Areas Requiring Attention", self.styles['CustomSubtitle']))
            
            for category, assessment in non_compliant[:3]:  # Top 3 issues
                elements.append(Paragraph(f"<b>{category.value}</b>", self.styles['SectionHeader']))
                
                for finding in assessment.findings[:2]:  # Top 2 findings
                    elements.append(Paragraph(f"• {finding}", self.styles['CustomBody']))
                
                for recommendation in assessment.recommendations[:2]:  # Top 2 recommendations
                    elements.append(Paragraph(f"→ {recommendation}", self.styles['CustomBody']))
                
                elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _create_statistics_section(self, report: OWASPComplianceReport) -> List:
        """Create statistics section"""
        elements = []
        
        elements.append(Paragraph("Security Statistics", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.1*inch))
        
        # Calculate additional statistics
        block_rate = (report.blocked_scans / report.total_scans * 100) if report.total_scans > 0 else 0
        
        stats_data = [
            ['Metric', 'Value'],
            ['Total Security Scans', f"{report.total_scans:,}"],
            ['Successfully Blocked', f"{report.blocked_scans:,}"],
            ['Block Rate', f"{block_rate:.1f}%"],
            ['Security Incidents', f"{report.incidents}"],
            ['High-Risk Incidents', f"{report.high_risk_incidents}"],
            ['Assessment Period', f"{(report.period_end - report.period_start).days} days"]
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#28A745')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8F9FA')),
            ('TEXTCOLOR', (0, 1), (-1, -1), black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#DEE2E6'))
        ]))
        
        elements.append(stats_table)
        
        return elements
    
    def _create_priority_actions(self, report: OWASPComplianceReport) -> List:
        """Create priority actions section"""
        elements = []
        
        elements.append(Paragraph("Priority Action Items", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.1*inch))
        
        if report.priority_actions:
            for i, action in enumerate(report.priority_actions, 1):
                elements.append(Paragraph(f"{i}. {action}", self.styles['CustomBody']))
                elements.append(Spacer(1, 0.05*inch))
        else:
            elements.append(Paragraph("No priority actions identified - all categories are compliant!", 
                                    self.styles['CustomBody']))
        
        return elements
    
    def _get_status_color(self, status: ComplianceStatus) -> str:
        """Get color for compliance status"""
        color_map = {
            ComplianceStatus.COMPLIANT: '#28A745',      # Green
            ComplianceStatus.PARTIALLY_COMPLIANT: '#FFC107',  # Yellow
            ComplianceStatus.NON_COMPLIANT: '#DC3545',  # Red
            ComplianceStatus.NOT_ASSESSED: '#6C757D'     # Gray
        }
        return color_map.get(status, '#6C757D')
    
    def _get_score_status(self, score: float) -> str:
        """Get status text for score"""
        if score >= 0.9:
            return "Excellent"
        elif score >= 0.8:
            return "Good"
        elif score >= 0.7:
            return "Fair"
        elif score >= 0.6:
            return "Poor"
        else:
            return "Critical"
    
    def _add_header_footer(self, canvas_obj, doc):
        """Add header and footer to each page"""
        canvas_obj.saveState()
        
        # Header
        canvas_obj.setFillColor(HexColor('#2C3E50'))
        canvas_obj.setFont('Helvetica-Bold', 10)
        canvas_obj.drawString(inch, doc.height + 0.5*inch, "SentinelShield AI Security Platform")
        canvas_obj.drawRightString(doc.width + inch, doc.height + 0.5*inch, "OWASP LLM Top 10 Compliance")
        
        # Footer
        canvas_obj.setFillColor(HexColor('#6C757D'))
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.drawString(inch, 0.5*inch, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        canvas_obj.drawRightString(doc.width + inch, 0.5*inch, f"Page {doc.page}")
        
        # Footer line
        canvas_obj.setStrokeColor(HexColor('#DEE2E6'))
        canvas_obj.line(inch, 0.75*inch, doc.width + inch, 0.75*inch)
        
        canvas_obj.restoreState()
    
    def generate_security_assessment_report(self, data: Dict[str, Any],
                                         output_path: str = None) -> str:
        """Generate general security assessment PDF report"""
        if output_path is None:
            output_path = f"security_assessment_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []
        
        # Title
        story.append(Paragraph("Security Assessment Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))
        
        # Add content based on data
        for section, content in data.items():
            story.append(Paragraph(section.replace('_', ' ').title(), self.styles['SectionHeader']))
            story.append(Spacer(1, 0.1*inch))
            
            if isinstance(content, list):
                for item in content:
                    story.append(Paragraph(f"• {item}", self.styles['CustomBody']))
            else:
                story.append(Paragraph(str(content), self.styles['CustomBody']))
            
            story.append(Spacer(1, 0.2*inch))
        
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
        
        logger.info(f"Security assessment PDF report generated: {output_path}")
        return output_path


# Global PDF generator instance
if REPORTLAB_AVAILABLE:
    pdf_generator = PDFGenerator()
else:
    pdf_generator = None
    logger.warning("PDF generator not available due to missing ReportLab dependency")
