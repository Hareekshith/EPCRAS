from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from epcras.models.user import Role
from epcras.models.vulnerability import Severity
from epcras.services.auth_service import role_required
from epcras.services.compliance_service import (
    run_compliance_analysis, get_compliance_summary, get_non_compliant_findings,
    get_asset_compliance_detail
)

compliance_bp = Blueprint('compliance', __name__, url_prefix='/compliance')

@compliance_bp.route('/', methods=['GET'])
@login_required
def overview():
    summary = get_compliance_summary()
    recent_findings = get_non_compliant_findings()[:10]
    return render_template('compliance/index.html', summary=summary, recent_findings=recent_findings)

@compliance_bp.route('/run', methods=['POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT, Role.SECURITY_ANALYST)
def run_analysis():
    asset_id_raw = request.form.get('asset_id') or request.args.get('asset_id')
    asset_id = int(asset_id_raw) if asset_id_raw and asset_id_raw.isdigit() else None

    result = run_compliance_analysis(asset_id=asset_id)
    
    scanned = result['scanned_installations']
    non_comp = result['non_compliant_findings']
    
    flash(
        f"Compliance analysis completed. Scanned {scanned} software record(s). "
        f"Detected {non_comp} non-compliant vulnerability finding(s).",
        'success' if non_comp == 0 else 'warning'
    )

    if asset_id:
        return redirect(url_for('compliance.asset_compliance', asset_id=asset_id))
    return redirect(url_for('compliance.overview'))

@compliance_bp.route('/non-compliant', methods=['GET'])
@login_required
def non_compliant():
    severity_filter = request.args.get('severity', '').strip()
    software_q = request.args.get('software', '').strip()

    findings = get_non_compliant_findings(
        severity=severity_filter if severity_filter in Severity.all_severities() else None,
        software=software_q if software_q else None
    )

    return render_template(
        'compliance/non_compliant.html',
        findings=findings,
        severities=Severity.all_severities(),
        severity_filter=severity_filter,
        software_q=software_q
    )

@compliance_bp.route('/assets/<int:asset_id>', methods=['GET'])
@login_required
def asset_compliance(asset_id):
    detail = get_asset_compliance_detail(asset_id)
    if not detail:
        flash('Asset not found.', 'danger')
        return redirect(url_for('compliance.overview'))

    return render_template('compliance/asset_detail.html', detail=detail)

@compliance_bp.route('/priority', methods=['GET'])
@login_required
def priority_queue():
    from epcras.services.priority_service import get_patch_priority_queue
    queue = get_patch_priority_queue()
    return render_template('compliance/priority_queue.html', queue=queue)

