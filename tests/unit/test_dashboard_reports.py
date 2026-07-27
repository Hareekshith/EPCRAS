import pytest
from epcras.models.asset import Asset, Criticality
from epcras.models.compliance import ComplianceResult, ComplianceStatus
from epcras.services.asset_service import create_asset, create_department
from epcras.services.software_service import get_or_create_software, add_installed_software
from epcras.services.vulnerability_service import create_vulnerability
from epcras.services.compliance_service import run_compliance_analysis
from epcras.services.dashboard_service import get_dashboard_metrics
from epcras.services.report_service import (
    ReportType, get_report_data, generate_csv_report, generate_pdf_report
)

def test_dashboard_metrics_calculation(app):
    dept = create_department("Engineering", "Dev team")
    asset1 = create_asset({'hostname': 'ENG-01', 'ip_address': '10.0.1.1', 'department_id': dept.id, 'criticality': Criticality.HIGH})
    asset2 = create_asset({'hostname': 'ENG-02', 'ip_address': '10.0.1.2', 'department_id': dept.id, 'criticality': Criticality.LOW})

    sw1 = get_or_create_software("Log4j", "Apache")
    sw2 = get_or_create_software("Firefox", "Mozilla")

    add_installed_software(asset1.id, sw1.id, "2.14.0")
    add_installed_software(asset2.id, sw2.id, "128.0")

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
    create_vulnerability({
        'cve_id': 'CVE-2024-0000',
        'software': 'Firefox',
        'vendor': 'Mozilla',
        'cvss_score': 4.0,
        'severity': 'MEDIUM',
        'affected_versions': '< 120.0',
        'fixed_version': '120.0',
        'patch_available': True
    })


    run_compliance_analysis()
    data = get_dashboard_metrics()
    metrics = data['metrics']

    assert metrics['total_assets'] == 2
    assert metrics['non_compliant_assets'] == 1
    assert metrics['compliant_assets'] == 1
    assert metrics['overall_compliance_percentage'] == 50.0
    assert metrics['critical_vulnerabilities'] == 1
    assert metrics['high_risk_assets'] >= 1
    assert metrics['vulnerabilities_with_patches'] == 1

def test_report_generation_csv(app):
    dept = create_department("IT", "IT Support")
    asset = create_asset({'hostname': 'IT-01', 'ip_address': '10.0.2.1', 'department_id': dept.id})
    sw = get_or_create_software("Log4j", "Apache")
    add_installed_software(asset.id, sw.id, "2.14.0")

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
    run_compliance_analysis()

    for rtype in ReportType.all_types():
        csv_str = generate_csv_report(rtype)
        assert isinstance(csv_str, str)
        assert "Generated At:" in csv_str
        assert "--- SUMMARY METRICS ---" in csv_str
        assert "--- DETAILED RECORDS ---" in csv_str

def test_report_generation_pdf(app):
    dept = create_department("Security", "SecOps")
    asset = create_asset({'hostname': 'SEC-01', 'ip_address': '10.0.3.1', 'department_id': dept.id})
    sw = get_or_create_software("Log4j", "Apache")
    add_installed_software(asset.id, sw.id, "2.14.0")

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
    run_compliance_analysis()

    for rtype in ReportType.all_types():
        pdf_bytes = generate_pdf_report(rtype)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b'%PDF')
