from flask import Blueprint, render_template, request
from flask_login import login_required
from epcras.models.user import Role
from epcras.models.asset import Criticality
from epcras.models.vulnerability import Severity
from epcras.models.compliance import ComplianceStatus
from epcras.services.search_service import search_system

search_bp = Blueprint('search', __name__, url_prefix='/search')

@search_bp.route('/', methods=['GET'])
@login_required
def index():
    params = {
        'hostname': request.args.get('hostname', '').strip(),
        'ip_address': request.args.get('ip_address', '').strip(),
        'department': request.args.get('department', '').strip(),
        'software': request.args.get('software', '').strip(),
        'cve_id': request.args.get('cve_id', '').strip(),
        'severity': request.args.get('severity', '').strip(),
        'compliance_status': request.args.get('compliance_status', '').strip(),
        'criticality': request.args.get('criticality', '').strip()
    }

    page = request.args.get('page', 1, type=int)
    search_results = search_system(params, page=page, per_page=15)

    return render_template(
        'search/index.html',
        results=search_results,
        params=params,
        severities=Severity.all_severities(),
        criticalities=Criticality.all_levels(),
        compliance_statuses=ComplianceStatus.all_statuses()
    )
