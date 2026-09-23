import math
from epcras.extensions import db
from epcras.models.asset import Asset, Department, Criticality
from epcras.models.software import Software, InstalledSoftware
from epcras.models.vulnerability import Vulnerability, Severity
from epcras.models.compliance import ComplianceResult, ComplianceStatus

def search_system(params: dict, page: int = 1, per_page: int = 15) -> dict:
    """
    Centralized multi-parameter search and filtering service across IT Assets,
    Vulnerabilities, and Non-Compliant findings.
    Supported parameters:
      - hostname, ip_address, department, software, cve_id, severity, compliance_status, criticality
    Paginates result sets efficiently.
    """
    hostname = params.get('hostname', '').strip()
    ip_address = params.get('ip_address', '').strip()
    dept_param = params.get('department', '').strip()
    software_param = params.get('software', '').strip()
    cve_param = params.get('cve_id', '').strip()
    severity_param = params.get('severity', '').strip().upper()
    compliance_param = params.get('compliance_status', '').strip().replace('-', '_')
    criticality_param = params.get('criticality', '').strip().upper()

    results = []

    # 1. Search Assets
    asset_query = Asset.query
    if hostname:
        asset_query = asset_query.filter(Asset.hostname.ilike(f"%{hostname}%"))
    if ip_address:
        asset_query = asset_query.filter(Asset.ip_address.ilike(f"%{ip_address}%"))
    if dept_param:
        asset_query = asset_query.join(Asset.department, isouter=True).filter(Department.name.ilike(f"%{dept_param}%"))
    if criticality_param and criticality_param in Criticality.all_levels():
        asset_query = asset_query.filter(Asset.criticality == criticality_param)

    if software_param:
        asset_query = asset_query.join(Asset.installed_software).join(InstalledSoftware.software).filter(Software.name.ilike(f"%{software_param}%"))

    if cve_param or (severity_param and severity_param in Severity.all_severities()):
        asset_query = asset_query.join(Asset.compliance_results)
        if cve_param:
            asset_query = asset_query.filter(ComplianceResult.cve_id.ilike(f"%{cve_param}%"))
        if severity_param and severity_param in Severity.all_severities():
            asset_query = asset_query.filter(ComplianceResult.severity == severity_param)

    asset_matches = asset_query.distinct().all()

    for asset in asset_matches:
        statuses = [item.compliance_status for item in asset.installed_software]
        if not statuses:
            asset_status = 'UNKNOWN'
        elif 'Non-Compliant' in statuses:
            asset_status = 'NON_COMPLIANT'
        elif all(s == 'Compliant' for s in statuses):
            asset_status = 'COMPLIANT'
        else:
            asset_status = 'UNKNOWN'

        if compliance_param and compliance_param.upper() != asset_status.upper():
            continue

        dept_name = asset.department.name if asset.department else 'Unassigned'
        results.append({
            "type": "ASSET",
            "title": f"Asset: {asset.hostname}",
            "subtitle": f"IP: {asset.ip_address} | Dept: {dept_name} | Criticality: {asset.criticality}",
            "status": asset_status,
            "link_url": f"/compliance/assets/{asset.id}",
            "badge_color": "success" if asset_status == 'COMPLIANT' else ("danger" if asset_status == 'NON_COMPLIANT' else "secondary")
        })

    # 2. Search Vulnerabilities
    if not (hostname or ip_address or dept_param or criticality_param or compliance_param):
        vuln_query = Vulnerability.query
        if cve_param:
            vuln_query = vuln_query.filter(Vulnerability.cve_id.ilike(f"%{cve_param}%"))
        if software_param:
            vuln_query = vuln_query.filter(Vulnerability.software.ilike(f"%{software_param}%"))
        if severity_param and severity_param in Severity.all_severities():
            vuln_query = vuln_query.filter(Vulnerability.severity == severity_param)

        vuln_matches = vuln_query.all()
        for v in vuln_matches:
            results.append({
                "type": "VULNERABILITY",
                "title": f"CVE: {v.cve_id}",
                "subtitle": f"Software: {v.software} | Vendor: {v.vendor} | CVSS: {v.cvss_score}",
                "status": v.severity,
                "link_url": f"/vulnerabilities/{v.id}",
                "badge_color": "danger" if v.severity in ('CRITICAL', 'HIGH') else "warning"
            })

    # Pagination logic
    total = len(results)
    page = max(1, int(page))
    per_page = max(1, int(per_page))
    total_pages = math.ceil(total / per_page) if total > 0 else 1

    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_items = results[start_idx:end_idx]

    return {
        "results_list": paginated_items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": total_pages
    }

