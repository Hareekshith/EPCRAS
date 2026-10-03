from datetime import datetime, timezone
from epcras.extensions import db
from epcras.models.asset import Asset
from epcras.models.software import Software, InstalledSoftware
from epcras.models.vulnerability import Vulnerability, Severity
from epcras.models.compliance import ComplianceResult, ComplianceStatus
from epcras.utils.version import is_version_vulnerable, parse_version
from epcras.services.audit_service import log_audit_event

def run_compliance_analysis(asset_id: int = None) -> dict:
    """
    Run automated compliance analysis against installed software records.
    Evaluates installed versions against vulnerability records.
    Updates InstalledSoftware.compliance_status and persists ComplianceResult records.
    """
    query = InstalledSoftware.query
    if asset_id:
        query = query.filter_by(asset_id=asset_id)

    installed_items = query.all()

    # Clear existing compliance results for targeted installed software items
    installed_ids = [item.id for item in installed_items]
    if installed_ids:
        ComplianceResult.query.filter(ComplianceResult.installed_software_id.in_(installed_ids)).delete(synchronize_session='fetch')

    scanned_count = len(installed_items)
    non_compliant_count = 0
    compliant_count = 0
    unknown_count = 0

    for item in installed_items:
        sw = item.software
        sw_name = sw.name if sw else "Unknown"
        installed_ver = item.version

        # Find vulnerabilities matching software name
        vulns = Vulnerability.query.filter(db.func.lower(Vulnerability.software) == sw_name.lower()).all()

        non_compliant_found = False
        has_unknown = False
        findings_created = False

        if not vulns:
            # Missing vulnerability data -> UNKNOWN status
            item.compliance_status = 'Unknown'
            comp_res = ComplianceResult(
                asset_id=item.asset_id,
                installed_software_id=item.id,
                software_name=sw_name,
                installed_version=installed_ver,
                status=ComplianceStatus.UNKNOWN
            )
            db.session.add(comp_res)
            unknown_count += 1
            continue

        # Check installed version against each matching vulnerability
        for vuln in vulns:
            is_vuln = is_version_vulnerable(
                installed_version_str=installed_ver,
                affected_versions_str=vuln.affected_versions,
                fixed_version_str=vuln.fixed_version
            )

            if is_vuln is True:
                # Found non-compliant vulnerability
                non_compliant_found = True
                comp_res = ComplianceResult(
                    asset_id=item.asset_id,
                    installed_software_id=item.id,
                    software_name=sw_name,
                    installed_version=installed_ver,
                    status=ComplianceStatus.NON_COMPLIANT,
                    cve_id=vuln.cve_id,
                    cvss_score=vuln.cvss_score,
                    severity=vuln.severity,
                    fixed_version=vuln.fixed_version,
                    patch_available=vuln.patch_available
                )
                db.session.add(comp_res)
                non_compliant_count += 1
                findings_created = True

            elif is_vuln is None:
                has_unknown = True

        if non_compliant_found:
            item.compliance_status = 'Non-Compliant'
        elif has_unknown:
            item.compliance_status = 'Unknown'
            comp_res = ComplianceResult(
                asset_id=item.asset_id,
                installed_software_id=item.id,
                software_name=sw_name,
                installed_version=installed_ver,
                status=ComplianceStatus.UNKNOWN
            )
            db.session.add(comp_res)
            unknown_count += 1
        else:
            # Evaluated against all matching vulns and clean -> COMPLIANT
            item.compliance_status = 'Compliant'
            comp_res = ComplianceResult(
                asset_id=item.asset_id,
                installed_software_id=item.id,
                software_name=sw_name,
                installed_version=installed_ver,
                status=ComplianceStatus.COMPLIANT
            )
            db.session.add(comp_res)
            compliant_count += 1

    db.session.commit()

    # Generate notifications for non-compliant assets (deduplicated by condition_key)
    from epcras.services.notification_service import create_notification
    non_comp_assets = Asset.query.join(Asset.installed_software).filter(InstalledSoftware.compliance_status == 'Non-Compliant').distinct().all()
    for nca in non_comp_assets:
        create_notification(
            condition_key=f"NON_COMPLIANT_ASSET:{nca.id}",
            title=f"Asset Non-Compliant: {nca.hostname}",
            message=f"Asset '{nca.hostname}' ({nca.ip_address}) was evaluated as Non-Compliant with active vulnerability findings.",
            severity='HIGH',
            link_url=f"/compliance/assets/{nca.id}"
        )

    target_desc = f"Asset ID {asset_id}" if asset_id else "All Assets"
    log_audit_event(
        action_category='COMPLIANCE_SCAN',
        target_entity=target_desc,
        details=f"Compliance analysis completed for {scanned_count} software installations. Non-Compliant findings: {non_compliant_count}, Compliant: {compliant_count}, Unknown: {unknown_count}",
        status='SUCCESS'
    )


    return {
        "scanned_installations": scanned_count,
        "non_compliant_findings": non_compliant_count,
        "compliant_count": compliant_count,
        "unknown_count": unknown_count
    }


def get_compliance_summary() -> dict:
    """Calculate aggregate compliance statistics across all assets."""
    assets = Asset.query.all()
    total_assets = len(assets)

    compliant_assets = 0
    non_compliant_assets = 0
    unknown_assets = 0

    for asset in assets:
        statuses = [item.compliance_status for item in asset.installed_software]
        if not statuses:
            unknown_assets += 1
        elif 'Non-Compliant' in statuses:
            non_compliant_assets += 1
        elif all(s == 'Compliant' for s in statuses):
            compliant_assets += 1
        else:
            unknown_assets += 1

    compliance_rate = round((compliant_assets / total_assets * 100), 1) if total_assets > 0 else 0.0

    non_compliant_results = ComplianceResult.query.filter_by(status=ComplianceStatus.NON_COMPLIANT).all()
    total_findings = len(non_compliant_results)

    critical_count = sum(1 for r in non_compliant_results if r.severity == Severity.CRITICAL)
    high_count = sum(1 for r in non_compliant_results if r.severity == Severity.HIGH)
    medium_count = sum(1 for r in non_compliant_results if r.severity == Severity.MEDIUM)
    low_count = sum(1 for r in non_compliant_results if r.severity == Severity.LOW)

    return {
        "total_assets": total_assets,
        "compliant_assets": compliant_assets,
        "non_compliant_assets": non_compliant_assets,
        "unknown_assets": unknown_assets,
        "compliance_rate": compliance_rate,
        "total_findings": total_findings,
        "critical_findings": critical_count,
        "high_findings": high_count,
        "medium_findings": medium_count,
        "low_findings": low_count
    }

def get_non_compliant_findings(asset_id: int = None, severity: str = None, software: str = None):
    """Retrieve detailed non-compliant findings with optional filtering."""
    query = ComplianceResult.query.filter_by(status=ComplianceStatus.NON_COMPLIANT)

    if asset_id:
        query = query.filter(ComplianceResult.asset_id == asset_id)

    if severity and severity.upper() in Severity.all_severities():
        query = query.filter(ComplianceResult.severity == severity.upper())

    if software:
        query = query.filter(ComplianceResult.software_name.ilike(f"%{software.strip()}%"))

    return query.order_by(ComplianceResult.cvss_score.desc(), ComplianceResult.cve_id.asc()).all()

def get_asset_compliance_detail(asset_id: int) -> dict:
    """Retrieve compliance status and non-compliant findings for a specific asset."""
    asset = db.session.get(Asset, asset_id)
    if not asset:
        return None

    installed_items = asset.installed_software.all()
    findings = ComplianceResult.query.filter_by(asset_id=asset_id, status=ComplianceStatus.NON_COMPLIANT).all()

    statuses = [item.compliance_status for item in installed_items]
    if not statuses:
        overall_status = 'UNKNOWN'
    elif 'Non-Compliant' in statuses:
        overall_status = 'NON_COMPLIANT'
    elif all(s == 'Compliant' for s in statuses):
        overall_status = 'COMPLIANT'
    else:
        overall_status = 'UNKNOWN'

    return {
        "asset": asset,
        "overall_status": overall_status,
        "installed_software": installed_items,
        "findings": findings
    }
