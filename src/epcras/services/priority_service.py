from datetime import datetime, timezone
from typing import List, Dict, Any
from epcras.extensions import db
from epcras.models.asset import Asset, Criticality
from epcras.models.vulnerability import Vulnerability, Severity
from epcras.models.compliance import ComplianceResult, ComplianceStatus

def calculate_vulnerability_priority(vulnerability_id: int) -> Dict[str, Any]:
    """
    Calculate deterministic patch priority score (0-100) and factor breakdown for a vulnerability.
    Weights:
      CVSS: 35%
      Asset Criticality: 25%
      Exploit Availability: 15%
      Affected Asset Count: 10%
      Vulnerability Age: 10%
      Patch Availability: 5%
    """
    vuln = db.session.get(Vulnerability, vulnerability_id)
    if not vuln:
        raise ValueError(f"Vulnerability ID {vulnerability_id} not found.")

    total_assets = Asset.query.count()

    # Query non-compliant findings associated with this vulnerability
    non_comp_results = ComplianceResult.query.filter(
        ComplianceResult.status == ComplianceStatus.NON_COMPLIANT,
        db.or_(
            ComplianceResult.cve_id == vuln.cve_id,
            db.func.lower(ComplianceResult.software_name) == vuln.software.lower()
        )
    ).all()


    affected_assets = list({res.asset for res in non_comp_results if res.asset})
    affected_count = len(affected_assets)

    # 1. CVSS Score Normalization (35%)
    cvss_norm = min(1.0, max(0.0, float(vuln.cvss_score) / 10.0))
    cvss_pts = round(35.0 * cvss_norm, 1)

    # 2. Asset Criticality Normalization (25%)
    crit_order = {Criticality.CRITICAL: 1.0, Criticality.HIGH: 0.75, Criticality.MEDIUM: 0.5, Criticality.LOW: 0.25}
    if affected_assets:
        max_crit_val = max(crit_order.get(a.criticality, 0.25) for a in affected_assets)
        max_crit_name = next(a.criticality for a in affected_assets if crit_order.get(a.criticality, 0.25) == max_crit_val)
    else:
        max_crit_val = 0.0
        max_crit_name = "None"

    crit_pts = round(25.0 * max_crit_val, 1)

    # 3. Exploit Availability Normalization (15%)
    exploit_norm = 1.0 if vuln.exploit_available else 0.0
    exploit_pts = round(15.0 * exploit_norm, 1)

    # 4. Affected Asset Count Normalization (10%)
    if total_assets > 0:
        asset_norm = min(1.0, float(affected_count) / float(total_assets))
    else:
        asset_norm = 0.0
    asset_pts = round(10.0 * asset_norm, 1)

    # 5. Vulnerability Age Normalization (10%)
    if vuln.published_date:
        now_date = datetime.now(timezone.utc).date()
        days_old = max(0, (now_date - vuln.published_date).days)
        age_norm = min(1.0, float(days_old) / 365.0)
    else:
        days_old = None
        age_norm = 0.5

    age_pts = round(10.0 * age_norm, 1)

    # 6. Patch Availability Normalization (5%)
    patch_norm = 1.0 if vuln.patch_available else 0.0
    patch_pts = round(5.0 * patch_norm, 1)

    # Composite Score (0-100)
    raw_score = cvss_pts + crit_pts + exploit_pts + asset_pts + age_pts + patch_pts
    final_score = int(round(raw_score))

    # Priority Tier Categorization
    if final_score >= 75:
        priority_tier = 'CRITICAL'
    elif final_score >= 50:
        priority_tier = 'HIGH'
    elif final_score >= 25:
        priority_tier = 'MEDIUM'
    else:
        priority_tier = 'LOW'

    # Human-Readable Explanations
    explanations = [
        f"CVSS {vuln.cvss_score} ({cvss_pts} pts)",
        f"{max_crit_name.title()} asset affected ({crit_pts} pts)" if max_crit_val > 0 else "No assets affected (0.0 pts)",
        f"Public exploit available ({exploit_pts} pts)" if vuln.exploit_available else f"No known public exploit ({exploit_pts} pts)",
        f"{affected_count} asset{'s' if affected_count != 1 else ''} affected ({asset_pts} pts)",
        f"Published {days_old} day{'s' if days_old != 1 else ''} ago ({age_pts} pts)" if days_old is not None else f"Published date unlisted ({age_pts} pts)",
        f"Patch available ({patch_pts} pts)" if vuln.patch_available else f"No patch available ({patch_pts} pts)"
    ]

    return {
        "vulnerability": vuln,
        "vulnerability_id": vuln.id,
        "cve_id": vuln.cve_id,
        "software": vuln.software,
        "vendor": vuln.vendor,
        "score": final_score,
        "priority": priority_tier,
        "affected_assets_count": affected_count,
        "affected_assets": affected_assets,
        "fixed_version": vuln.fixed_version or "N/A",
        "patch_available": vuln.patch_available,
        "exploit_available": vuln.exploit_available,
        "explanations": explanations,
        "factor_points": {
            "cvss": cvss_pts,
            "criticality": crit_pts,
            "exploit": exploit_pts,
            "assets": asset_pts,
            "age": age_pts,
            "patch": patch_pts
        }
    }

def get_patch_priority_queue() -> List[Dict[str, Any]]:
    """
    Get the complete Patch Priority Queue sorted by score descending (highest priority first).
    """
    vulnerabilities = Vulnerability.query.all()
    queue = []
    for vuln in vulnerabilities:
        p_data = calculate_vulnerability_priority(vuln.id)
        queue.append(p_data)

    # Sort highest priority score first
    queue.sort(key=lambda item: item['score'], reverse=True)
    return queue
