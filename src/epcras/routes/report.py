from flask import Blueprint, render_template, Response, flash, redirect, url_for
from flask_login import login_required
from epcras.services.report_service import ReportType, generate_csv_report, generate_pdf_report, get_report_data

report_bp = Blueprint('report', __name__, url_prefix='/reports')

@report_bp.route('/', methods=['GET'])
@login_required
def index():
    report_types = [
        {
            "id": ReportType.OVERALL_COMPLIANCE,
            "title": "Overall Compliance Report",
            "description": "Comprehensive summary of organization-wide asset compliance posture, total assets, compliance rate, and per-asset status.",
            "icon": "bi-shield-check"
        },
        {
            "id": ReportType.ASSET_COMPLIANCE,
            "title": "Asset-Wise Compliance Inventory Report",
            "description": "Detailed breakdown of every asset and its installed software inventory with individual patch compliance statuses.",
            "icon": "bi-pc-display"
        },
        {
            "id": ReportType.DEPARTMENT_COMPLIANCE,
            "title": "Department-Wise Compliance Report",
            "description": "Grouped metrics by department showing compliant, non-compliant, and unknown asset distributions per organizational unit.",
            "icon": "bi-building"
        },
        {
            "id": ReportType.CRITICAL_VULNERABILITY,
            "title": "Critical & High Vulnerability Risk Report",
            "description": "Targeted report focusing on all active non-compliant findings with Critical and High severity, CVSS scores, and patch availability.",
            "icon": "bi-exclamation-triangle-fill"
        },
        {
            "id": ReportType.PATCH_PRIORITY,
            "title": "Patch Priority Queue Report",
            "description": "Ranked remediation report listing vulnerabilities prioritized by deterministic 0–100 score, factor weights, and fixed versions.",
            "icon": "bi-list-ol"
        }
    ]

    return render_template('reports/index.html', report_types=report_types)

@report_bp.route('/export/<report_type>/<export_format>', methods=['GET'])
@login_required
def export_report(report_type, export_format):
    if report_type not in ReportType.all_types():
        flash('Invalid report type requested.', 'danger')
        return redirect(url_for('report.index'))

    fmt = export_format.lower()
    if fmt == 'csv':
        content = generate_csv_report(report_type)
        filename = f"{report_type.lower()}_report.csv"
        return Response(
            content,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    elif fmt == 'pdf':
        content_bytes = generate_pdf_report(report_type)
        filename = f"{report_type.lower()}_report.pdf"
        return Response(
            content_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    else:
        flash('Invalid export format requested. Supported formats: PDF, CSV.', 'danger')
        return redirect(url_for('report.index'))
