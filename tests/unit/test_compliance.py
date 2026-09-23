import pytest
from epcras.models.user import Role
from epcras.models.asset import Asset, Criticality
from epcras.models.software import Software
from epcras.models.vulnerability import Vulnerability, Severity
from epcras.services.asset_service import create_asset
from epcras.services.software_service import get_or_create_software, add_installed_software
from epcras.services.vulnerability_service import create_vulnerability
from epcras.models.compliance import ComplianceResult, ComplianceStatus
from epcras.services.compliance_service import (
    run_compliance_analysis, get_compliance_summary, get_non_compliant_findings,
    get_asset_compliance_detail
)

def test_compliance_software_no_vulnerabilities_returns_unknown(app):
    asset = create_asset({'hostname': 'SERVER-01', 'ip_address': '10.0.0.1'})
    sw = get_or_create_software("UnknownCustomApp", "InternalVendor")
    installed = add_installed_software(asset.id, sw.id, "1.0.0")

    result = run_compliance_analysis(asset.id)
    assert result['scanned_installations'] == 1
    assert result['unknown_count'] == 1
    assert installed.compliance_status == 'Unknown'

def test_compliance_vulnerable_installed_version_returns_non_compliant(app):
    asset = create_asset({'hostname': 'SERVER-02', 'ip_address': '10.0.0.2'})
    sw = get_or_create_software("Log4j", "Apache")
    installed = add_installed_software(asset.id, sw.id, "2.14.0")

    create_vulnerability({
        'cve_id': 'CVE-2021-44228',
        'software': 'Log4j',
        'vendor': 'Apache',
        'cvss_score': 10.0,
        'severity': 'CRITICAL',
        'affected_versions': '2.0 <= 2.14.1',
        'fixed_version': '2.17.1',
        'patch_available': True
    })

    result = run_compliance_analysis(asset.id)
    assert result['non_compliant_findings'] == 1
    assert installed.compliance_status == 'Non-Compliant'

    findings = get_non_compliant_findings(asset_id=asset.id)
    assert len(findings) == 1
    assert findings[0].cve_id == 'CVE-2021-44228'
    assert findings[0].cvss_score == 10.0

def test_compliance_patched_installed_version_returns_compliant(app):
    asset = create_asset({'hostname': 'SERVER-03', 'ip_address': '10.0.0.3'})
    sw = get_or_create_software("xz-utils", "Tukaani")
    installed = add_installed_software(asset.id, sw.id, "5.6.2")

    create_vulnerability({
        'cve_id': 'CVE-2024-3094',
        'software': 'xz-utils',
        'vendor': 'Tukaani',
        'cvss_score': 10.0,
        'severity': 'CRITICAL',
        'affected_versions': '5.6.0, 5.6.1',
        'fixed_version': '5.6.2',
        'patch_available': True
    })

    result = run_compliance_analysis(asset.id)
    assert result['compliant_count'] == 1
    assert installed.compliance_status == 'Compliant'

def test_compliance_multiple_vulnerabilities_single_software(app):
    asset = create_asset({'hostname': 'SERVER-04', 'ip_address': '10.0.0.4'})
    sw = get_or_create_software("OpenSSL", "OpenSSL Project")
    installed = add_installed_software(asset.id, sw.id, "1.1.1f")

    create_vulnerability({
        'cve_id': 'CVE-2021-3711',
        'software': 'OpenSSL',
        'vendor': 'OpenSSL Project',
        'cvss_score': 9.8,
        'severity': 'CRITICAL',
        'affected_versions': '< 1.1.1l',
        'fixed_version': '1.1.1l',
        'patch_available': True
    })
    create_vulnerability({
        'cve_id': 'CVE-2022-0778',
        'software': 'OpenSSL',
        'vendor': 'OpenSSL Project',
        'cvss_score': 7.5,
        'severity': 'HIGH',
        'affected_versions': '< 1.1.1n',
        'fixed_version': '1.1.1n',
        'patch_available': True
    })

    result = run_compliance_analysis(asset.id)
    assert result['non_compliant_findings'] == 2
    assert installed.compliance_status == 'Non-Compliant'

    findings = get_non_compliant_findings(asset_id=asset.id)
    assert len(findings) == 2
    cves = [f.cve_id for f in findings]
    assert 'CVE-2021-3711' in cves
    assert 'CVE-2022-0778' in cves

def test_compliance_unparseable_version_returns_unknown(app):
    asset = create_asset({'hostname': 'SERVER-05', 'ip_address': '10.0.0.5'})
    sw = get_or_create_software("CustomTool", "Vendor")
    installed = add_installed_software(asset.id, sw.id, "build-2024-invalid")

    create_vulnerability({
        'cve_id': 'CVE-2024-9999',
        'software': 'CustomTool',
        'vendor': 'Vendor',
        'cvss_score': 7.0,
        'severity': 'HIGH',
        'affected_versions': '< 2.0.0'
    })

    result = run_compliance_analysis(asset.id)
    assert result['unknown_count'] == 1
    assert installed.compliance_status == 'Unknown'

def test_compliance_summary_stats(app):
    a1 = create_asset({'hostname': 'A1', 'ip_address': '10.0.0.10'})
    sw1 = get_or_create_software("AppA", "VendorA")
    add_installed_software(a1.id, sw1.id, "1.0.0")

    create_vulnerability({
        'cve_id': 'CVE-2024-0001',
        'software': 'AppA',
        'vendor': 'VendorA',
        'cvss_score': 9.0,
        'severity': 'CRITICAL',
        'affected_versions': '1.0.0',
        'fixed_version': '1.0.1'
    })

    run_compliance_analysis()
    summary = get_compliance_summary()
    assert summary['total_assets'] == 1
    assert summary['non_compliant_assets'] == 1
    assert summary['compliance_rate'] == 0.0
    assert summary['critical_findings'] == 1

def test_compliance_summary_zero_assets(app):
    summary = get_compliance_summary()
    assert summary['total_assets'] == 0
    assert summary['compliance_rate'] == 0.0
    assert summary['total_findings'] == 0

def test_targeted_asset_compliance_analysis(app):
    a1 = create_asset({'hostname': 'TARGET-A1', 'ip_address': '10.0.0.1'})
    a2 = create_asset({'hostname': 'TARGET-A2', 'ip_address': '10.0.0.2'})

    sw = get_or_create_software("VulnApp", "V")
    add_installed_software(a1.id, sw.id, "1.0.0")
    add_installed_software(a2.id, sw.id, "1.0.0")

    create_vulnerability({
        'cve_id': 'CVE-2024-TARGET',
        'software': 'VulnApp',
        'vendor': 'V',
        'cvss_score': 8.0,
        'severity': 'HIGH',
        'affected_versions': '1.0.0'
    })

    # Run analysis ONLY on a1
    res1 = run_compliance_analysis(asset_id=a1.id)
    assert res1['scanned_installations'] == 1
    assert res1['non_compliant_findings'] == 1

    findings_a1 = ComplianceResult.query.filter_by(asset_id=a1.id).all()
    assert len(findings_a1) == 1

    findings_a2 = ComplianceResult.query.filter_by(asset_id=a2.id).all()
    assert len(findings_a2) == 0  # Untouched

def test_asset_compliance_detail_service(app):
    asset = create_asset({'hostname': 'DETAIL-HOST', 'ip_address': '10.0.0.3'})

    # No software installed -> UNKNOWN
    d_empty = get_asset_compliance_detail(asset.id)
    assert d_empty['overall_status'] == 'UNKNOWN'

    # Nonexistent asset
    assert get_asset_compliance_detail(999999) is None

    # Install compliant software
    sw = get_or_create_software("CleanApp", "V")
    add_installed_software(asset.id, sw.id, "2.0.0")
    create_vulnerability({
        'cve_id': 'CVE-2024-CLEAN',
        'software': 'CleanApp',
        'vendor': 'V',
        'cvss_score': 5.0,
        'severity': 'MEDIUM',
        'affected_versions': '< 1.0.0',
        'fixed_version': '1.0.0'
    })
    run_compliance_analysis(asset.id)

    d_clean = get_asset_compliance_detail(asset.id)
    assert d_clean['overall_status'] == 'COMPLIANT'
    assert len(d_clean['installed_software']) == 1

def test_compliance_result_repr_and_statuses(app):
    comp = ComplianceResult(
        asset_id=1,
        installed_software_id=1,
        software_name="ReprSoft",
        installed_version="1.0.0",
        status=ComplianceStatus.NON_COMPLIANT,
        cve_id="CVE-2024-REPR"
    )
    assert "CVE-2024-REPR" in repr(comp)
    assert len(ComplianceStatus.all_statuses()) == 3

