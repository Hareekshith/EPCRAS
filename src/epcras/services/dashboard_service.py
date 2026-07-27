from epcras.extensions import db
from epcras.models.asset import Asset, Department, Criticality
from epcras.models.vulnerability import Severity
from epcras.models.compliance import ComplianceResult, ComplianceStatus

def get_dashboard_metrics() -> dict:
    """
    Calculate dynamic dashboard metrics and chart datasets derived directly from actual DB records.
    Never uses hardcoded metric values.
    """
    assets = Asset.query.all()
    total_assets = len(assets)

    compliant_assets = 0
    non_compliant_assets = 0
    unknown_assets = 0

    asset_criticality_counts = {
        Criticality.CRITICAL: 0,
        Criticality.HIGH: 0,
        Criticality.MEDIUM: 0,
        Criticality.LOW: 0
    }

    high_risk_asset_ids = set()

    for asset in assets:
        # Track criticality distribution
        crit = asset.criticality or Criticality.MEDIUM
        asset_criticality_counts[crit] = asset_criticality_counts.get(crit, 0) + 1

        if crit in (Criticality.HIGH, Criticality.CRITICAL):
            high_risk_asset_ids.add(asset.id)

        # Asset compliance classification
        statuses = [item.compliance_status for item in asset.installed_software]
        if not statuses:
            unknown_assets += 1
        elif 'Non-Compliant' in statuses:
            non_compliant_assets += 1
        elif all(s == 'Compliant' for s in statuses):
            compliant_assets += 1
        else:
            unknown_assets += 1

    overall_compliance_percentage = round((compliant_assets / total_assets * 100), 1) if total_assets > 0 else 0.0

    # Query Non-Compliant findings
    non_comp_results = ComplianceResult.query.filter_by(status=ComplianceStatus.NON_COMPLIANT).all()

    critical_vulnerabilities = 0
    high_vulnerabilities = 0
    medium_vulnerabilities = 0
    low_vulnerabilities = 0
    vulnerabilities_with_patches = 0

    for res in non_comp_results:
        sev = res.severity or 'MEDIUM'
        if sev == Severity.CRITICAL:
            critical_vulnerabilities += 1
            high_risk_asset_ids.add(res.asset_id)
        elif sev == Severity.HIGH:
            high_vulnerabilities += 1
        elif sev == Severity.MEDIUM:
            medium_vulnerabilities += 1
        elif sev == Severity.LOW:
            low_vulnerabilities += 1

        if res.patch_available:
            vulnerabilities_with_patches += 1

    # Department-wise compliance aggregation
    departments = Department.query.all()
    dept_compliance = {}

    # Include Unassigned department if assets exist with no department
    no_dept_assets = Asset.query.filter_by(department_id=None).all()
    if no_dept_assets:
        dept_compliance["Unassigned"] = {"compliant": 0, "non_compliant": 0, "unknown": 0}
        for asset in no_dept_assets:
            statuses = [item.compliance_status for item in asset.installed_software]
            if not statuses:
                dept_compliance["Unassigned"]["unknown"] += 1
            elif 'Non-Compliant' in statuses:
                dept_compliance["Unassigned"]["non_compliant"] += 1
            elif all(s == 'Compliant' for s in statuses):
                dept_compliance["Unassigned"]["compliant"] += 1
            else:
                dept_compliance["Unassigned"]["unknown"] += 1

    for dept in departments:
        dept_name = dept.name
        dept_compliance[dept_name] = {"compliant": 0, "non_compliant": 0, "unknown": 0}
        for asset in dept.assets:
            statuses = [item.compliance_status for item in asset.installed_software]
            if not statuses:
                dept_compliance[dept_name]["unknown"] += 1
            elif 'Non-Compliant' in statuses:
                dept_compliance[dept_name]["non_compliant"] += 1
            elif all(s == 'Compliant' for s in statuses):
                dept_compliance[dept_name]["compliant"] += 1
            else:
                dept_compliance[dept_name]["unknown"] += 1

    return {
        "metrics": {
            "total_assets": total_assets,
            "compliant_assets": compliant_assets,
            "non_compliant_assets": non_compliant_assets,
            "unknown_assets": unknown_assets,
            "overall_compliance_percentage": overall_compliance_percentage,
            "critical_vulnerabilities": critical_vulnerabilities,
            "high_risk_assets": len(high_risk_asset_ids),
            "vulnerabilities_with_patches": vulnerabilities_with_patches
        },
        "charts": {
            "compliance_distribution": {
                "Compliant": compliant_assets,
                "Non-Compliant": non_compliant_assets,
                "Unknown": unknown_assets
            },
            "severity_distribution": {
                "Critical": critical_vulnerabilities,
                "High": high_vulnerabilities,
                "Medium": medium_vulnerabilities,
                "Low": low_vulnerabilities
            },
            "asset_criticality": asset_criticality_counts,
            "department_compliance": dept_compliance
        }
    }
