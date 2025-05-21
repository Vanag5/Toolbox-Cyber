from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
import os
import uuid


def generate_pdf_report(scan_data, output_dir='/app/scan_reports'):
    """
    Generate a PDF report for a scan.
    """
    os.makedirs(output_dir, exist_ok=True)
    report_filename = f"{output_dir}/scan_report_{uuid.uuid4().hex[:8]}.pdf"
    doc = SimpleDocTemplate(report_filename, pagesize=letter)
    content = []
    styles = getSampleStyleSheet()

    # Add title
    content.append(Paragraph(
        f"Scan Report for {scan_data.get('target', 'Unknown')}", styles['Title']))
    content.append(Spacer(1, 12))

    # Add details
    details = [
        ['Scan Type', scan_data.get('scan_type', 'Unknown')],
        ['Target', scan_data.get('target', 'Unknown')],
        ['Timestamp', scan_data.get('timestamp', 'Unknown')]
    ]
    table = Table(details)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    content.append(table)
    content.append(Spacer(1, 12))

    # Add results
    results = scan_data.get('results', [])
    if results:
        content.append(Paragraph("Scan Results", styles['Heading2']))
        for result in results:
            content.append(Paragraph(
                f"Port: {result.get('port', 'N/A')}, State: {result.get('state', 'N/A')}", styles['Normal']))
            content.append(Spacer(1, 12))

    doc.build(content)
    return report_filename
