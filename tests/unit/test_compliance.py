import pytest
from epcras.models.user import Role
from epcras.models.asset import Asset, Criticality
from epcras.models.software import Software
from epcras.models.vulnerability import Vulnerability, Severity
from epcras.services.asset_service import create_asset
from epcras.services.software_service import get_or_create_software, add_installed_software
from epcras.services.vulnerability_service import create_vulnerability
from epcras.services.compliance_service import (
    run_compliance_analysis, get_compliance_summary, get_non_compliant_findings
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
