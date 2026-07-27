import csv
import io
from datetime import datetime, timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from epcras.models.asset import Asset, Department
from epcras.models.compliance import ComplianceResult, ComplianceStatus
from epcras.models.vulnerability import Severity
from epcras.services.dashboard_service import get_dashboard_metrics

class ReportType:
    OVERALL_COMPLIANCE = 'OVERALL_COMPLIANCE'
    ASSET_COMPLIANCE = 'ASSET_COMPLIANCE'
    DEPARTMENT_COMPLIANCE = 'DEPARTMENT_COMPLIANCE'
    CRITICAL_VULNERABILITY = 'CRITICAL_VULNERABILITY'
    PATCH_PRIORITY = 'PATCH_PRIORITY'

    @classmethod
    def all_types(cls):
        return [
            cls.OVERALL_COMPLIANCE,
            cls.ASSET_COMPLIANCE,
            cls.DEPARTMENT_COMPLIANCE,
            cls.CRITICAL_VULNERABILITY,
            cls.PATCH_PRIORITY
        ]


def get_report_data(report_type: str) -> dict:
    """
    Gathers report title, generation timestamp (UTC), summary metrics dict,
    headers list, and record rows for a specific report type.
    """
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    metrics_data = get_dashboard_metrics()
    metrics = metrics_data['metrics']

    if report_type == ReportType.OVERALL_COMPLIANCE:
        title = "EPCRAS Overall Patch Compliance Report"
        summary = {
            "Total Assets": metrics["total_assets"],
            "Compliant Assets": metrics["compliant_assets"],
            "Non-Compliant Assets": metrics["non_compliant_assets"],
            "Unknown Assets": metrics["unknown_assets"],
            "Compliance Rate": f"{metrics['overall_compliance_percentage']}%",
            "Total Active Vulnerabilities": metrics["critical_vulnerabilities"] + metrics["vulnerabilities_with_patches"]
        }
        headers = ["Asset Hostname", "IP Address", "OS", "Department", "Criticality", "Compliance Status", "Vulnerabilities"]
        rows = []
        assets = Asset.query.all()
        for asset in assets:
            statuses = [item.compliance_status for item in asset.installed_software]
            if not statuses:
                status_str = 'UNKNOWN'
            elif 'Non-Compliant' in statuses:
                status_str = 'NON_COMPLIANT'
            elif all(s == 'Compliant' for s in statuses):
                status_str = 'COMPLIANT'
            else:
                status_str = 'UNKNOWN'

            finding_count = ComplianceResult.query.filter_by(asset_id=asset.id, status=ComplianceStatus.NON_COMPLIANT).count()
            dept_name = asset.department.name if asset.department else 'Unassigned'
            rows.append([
                asset.hostname,
                asset.ip_address,
                f"{asset.operating_system} {asset.os_version or ''}".strip(),
                dept_name,
                asset.criticality,
                status_str,
                str(finding_count)
            ])

    elif report_type == ReportType.ASSET_COMPLIANCE:
        title = "EPCRAS Asset-Wise Compliance & Software Inventory Report"
        summary = {
            "Total Assets Evaluated": metrics["total_assets"],
            "Compliant Assets": metrics["compliant_assets"],
            "Non-Compliant Assets": metrics["non_compliant_assets"],
            "High-Risk Assets": metrics["high_risk_assets"]
        }
        headers = ["Asset Hostname", "Owner", "Software Name", "Vendor", "Installed Version", "Status"]
        rows = []
        assets = Asset.query.all()
        for asset in assets:
            if not asset.installed_software.all():
                rows.append([asset.hostname, asset.owner or 'N/A', 'None', 'N/A', 'N/A', 'UNKNOWN'])
            else:
                for item in asset.installed_software:
                    sw_name = item.software.name if item.software else 'Unknown'
                    vendor = item.software.vendor if item.software else 'Unknown'
                    rows.append([
                        asset.hostname,
                        asset.owner or 'N/A',
                        sw_name,
                        vendor,
                        item.version,
                        item.compliance_status.upper()
                    ])

    elif report_type == ReportType.DEPARTMENT_COMPLIANCE:
        title = "EPCRAS Department-Wise Compliance Summary Report"
        dept_comp = metrics_data['charts']['department_compliance']
        summary = {
            "Total Departments": len(dept_comp),
            "Overall Compliance Rate": f"{metrics['overall_compliance_percentage']}%",
            "Total Non-Compliant Assets": metrics["non_compliant_assets"]
        }
        headers = ["Department Name", "Total Assets", "Compliant Assets", "Non-Compliant Assets", "Unknown Assets", "Department Compliance %"]
        rows = []
        for dept_name, stats in dept_comp.items():
            tot = stats["compliant"] + stats["non_compliant"] + stats["unknown"]
            rate = round((stats["compliant"] / tot * 100), 1) if tot > 0 else 0.0
            rows.append([
                dept_name,
                str(tot),
                str(stats["compliant"]),
                str(stats["non_compliant"]),
                str(stats["unknown"]),
                f"{rate}%"
            ])

    elif report_type == ReportType.CRITICAL_VULNERABILITY:
        title = "EPCRAS Critical & High Vulnerability Risk Report"
        non_comp_results = ComplianceResult.query.filter(
            ComplianceResult.status == ComplianceStatus.NON_COMPLIANT,
            ComplianceResult.severity.in_([Severity.CRITICAL, Severity.HIGH])
        ).order_by(ComplianceResult.cvss_score.desc()).all()

        summary = {
            "Critical & High Findings Count": len(non_comp_results),
            "Critical Severity Count": metrics_data['charts']['severity_distribution']['Critical'],
            "High Severity Count": metrics_data['charts']['severity_distribution']['High'],
            "Patches Available": sum(1 for r in non_comp_results if r.patch_available)
        }
        headers = ["Asset Hostname", "Software", "Version", "CVE ID", "CVSS Score", "Severity", "Fixed Version", "Patch Status"]
        rows = []
        for r in non_comp_results:
            hostname = r.asset.hostname if r.asset else f"Asset #{r.asset_id}"
            patch_str = "Available" if r.patch_available else "Unavailable"
            rows.append([
                hostname,
                r.software_name,
                r.installed_version,
                r.cve_id or 'N/A',
                f"{r.cvss_score:.1f}" if r.cvss_score else 'N/A',
                r.severity or 'N/A',
                r.fixed_version or 'Unpatched',
                patch_str
            ])
    elif report_type == ReportType.PATCH_PRIORITY:
        from epcras.services.priority_service import get_patch_priority_queue
        title = "EPCRAS Patch Priority Queue & Remediations Report"
        queue = get_patch_priority_queue()

        summary = {
            "Total Queue Items": len(queue),
            "Critical Priority Items": len([item for item in queue if item["priority"] == "CRITICAL"]),
            "High Priority Items": len([item for item in queue if item["priority"] == "HIGH"]),
            "Patches Available": len([item for item in queue if item["patch_available"]]),
            "Exploits Public": len([item for item in queue if item["exploit_available"]])
        }
        headers = ["CVE ID", "Software Name", "Priority Score", "Priority Tier", "Affected Assets", "Fixed Version", "Patch Status", "Exploit Status", "Factor Explanations"]
        rows = []
        for item in queue:
            rows.append([
                item["cve_id"],
                item["software"],
                f"{item['score']}/100",
                item["priority"],
                str(item["affected_assets_count"]),
                item["fixed_version"],
                "Available" if item["patch_available"] else "Unavailable",
                "Public" if item["exploit_available"] else "None",
                "; ".join(item["explanations"])
            ])
    else:
        raise ValueError(f"Unknown report type '{report_type}'")


    return {
        "title": title,
        "timestamp": now_utc,
        "summary": summary,
        "headers": headers,
        "rows": rows
    }

def generate_csv_report(report_type: str) -> str:
    """Generate CSV string for the specified report type."""
    data = get_report_data(report_type)
    output = io.StringIO()
    writer = csv.writer(output)

    # Title & Timestamp Header
    writer.writerow([data["title"]])
    writer.writerow([f"Generated At: {data['timestamp']}"])
    writer.writerow([])

    # Summary Section
    writer.writerow(["--- SUMMARY METRICS ---"])
    for k, v in data["summary"].items():
        writer.writerow([k, v])
    writer.writerow([])

    # Records Table Header & Rows
    writer.writerow(["--- DETAILED RECORDS ---"])
    writer.writerow(data["headers"])
    for row in data["rows"]:
        writer.writerow(row)

    return output.getvalue()

def generate_pdf_report(report_type: str) -> bytes:
    """Generate PDF bytes for the specified report type using ReportLab."""
    data = get_report_data(report_type)
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=4
    )
    meta_style = ParagraphStyle(
        'DocMeta',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=12
    )
    section_style = ParagraphStyle(
        'DocSection',
        parent=styles['Heading3'],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor('#0284c7'),
        spaceAfter=6
    )
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=8,
        leading=10
    )
    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        fontName='Helvetica-Bold',
        textColor=colors.white
    )

    elements = []

    # Title & Generation Timestamp
    elements.append(Paragraph(data["title"], title_style))
    elements.append(Paragraph(f"Generated: {data['timestamp']} | EPCRAS Patch Compliance System", meta_style))
    elements.append(Spacer(1, 8))

    # Summary Block Table
    elements.append(Paragraph("Executive Summary", section_style))
    summary_table_data = []
    for k, v in data["summary"].items():
        summary_table_data.append([
            Paragraph(f"<b>{k}:</b>", table_cell_style),
            Paragraph(str(v), table_cell_style)
        ])

    sum_table = Table(summary_table_data, colWidths=[180, 320])
    sum_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(sum_table)
    elements.append(Spacer(1, 14))

    # Detailed Records Table
    elements.append(Paragraph("Detailed Records", section_style))
    header_cells = [Paragraph(h, table_header_style) for h in data["headers"]]
    table_data = [header_cells]

    for row in data["rows"]:
        row_cells = [Paragraph(str(cell), table_cell_style) for cell in row]
        table_data.append(row_cells)

    # Calculate column widths dynamically based on table size
    num_cols = len(data["headers"])
    col_width = 520 / num_cols if num_cols > 0 else 100

    rec_table = Table(table_data, colWidths=[col_width] * num_cols, repeatRows=1)
    rec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))

    elements.append(rec_table)

    doc.build(elements)
    return buffer.getvalue()
