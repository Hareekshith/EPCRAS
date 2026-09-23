from datetime import datetime, date, timedelta, timezone
import pytest
from epcras.models.asset import Asset, Criticality
from epcras.models.vulnerability import Vulnerability, Severity
from epcras.services.asset_service import create_asset
from epcras.services.software_service import get_or_create_software, add_installed_software
from epcras.services.vulnerability_service import create_vulnerability
from epcras.services.compliance_service import run_compliance_analysis
from epcras.services.priority_service import calculate_vulnerability_priority, get_patch_priority_queue
from epcras.services.report_service import ReportType, generate_csv_report, generate_pdf_report, get_report_data

def test_priority_score_exact_calculation(app):
    # Create 10 assets (1 CRITICAL asset)
    crit_asset = create_asset({'hostname': 'CRIT-SRV', 'ip_address': '10.0.0.1', 'criticality': Criticality.CRITICAL})
    for i in range(9):
        create_asset({'hostname': f'WORKSTATION-{i}', 'ip_address': f'10.0.0.1{i}', 'criticality': Criticality.LOW})

    sw = get_or_create_software("Log4j", "Apache")
    # Install on CRIT-SRV and 6 workstations (total 7 affected assets out of 10)
    add_installed_software(crit_asset.id, sw.id, "2.14.0")
    all_assets = Asset.query.all()
    for a in all_assets[1:7]:
        add_installed_software(a.id, sw.id, "2.14.0")

    # Log4Shell: CVSS 10.0, Exploit True, Patch True, Published 365 days ago
    pub_date = datetime.now(timezone.utc).date() - timedelta(days=365)
    vuln = create_vulnerability({
        'cve_id': 'CVE-2021-44228',
        'software': 'Log4j',
        'vendor': 'Apache',
        'cvss_score': 10.0,
        'severity': 'CRITICAL',
        'affected_versions': '2.0 <= 2.14.1',
        'fixed_version': '2.17.1',
        'patch_available': True,
        'exploit_available': True,
        'published_date': pub_date
    })

    run_compliance_analysis()

    p_data = calculate_vulnerability_priority(vuln.id)

    # Weights breakdown check:
    # CVSS (35%): 10.0/10.0 * 35.0 = 35.0
    # Criticality (25%): Max CRITICAL = 1.0 * 25.0 = 25.0
    # Exploit (15%): True = 1.0 * 15.0 = 15.0
    # Asset count (10%): 7 affected / 10 total = 0.7 * 10.0 = 7.0
    # Age (10%): 365 days / 365.0 = 1.0 * 10.0 = 10.0
    # Patch (5%): True = 1.0 * 5.0 = 5.0
    # Total = 35 + 25 + 15 + 7 + 10 + 5 = 97
    assert p_data['score'] == 97
    assert p_data['priority'] == 'CRITICAL'
    assert p_data['affected_assets_count'] == 7
    assert len(p_data['explanations']) == 6

def test_priority_tier_classification_thresholds(app):
    crit_asset = create_asset({'hostname': 'CRIT-SRV-2', 'ip_address': '10.0.0.2', 'criticality': Criticality.CRITICAL})
    sw1 = get_or_create_software("S1", "V1")
    add_installed_software(crit_asset.id, sw1.id, "1.0.0")

    v_crit = create_vulnerability({'cve_id': 'CVE-CRIT-1', 'software': 'S1', 'vendor': 'V1', 'cvss_score': 10.0, 'severity': 'CRITICAL', 'affected_versions': '1.0.0', 'exploit_available': True, 'patch_available': True})
    v_high = create_vulnerability({'cve_id': 'CVE-HIGH-1', 'software': 'S2', 'vendor': 'V2', 'cvss_score': 8.0, 'severity': 'HIGH', 'exploit_available': False, 'patch_available': True})
    v_low = create_vulnerability({'cve_id': 'CVE-LOW-1', 'software': 'S3', 'vendor': 'V3', 'cvss_score': 2.0, 'severity': 'LOW', 'exploit_available': False, 'patch_available': False})

    run_compliance_analysis()

    res_crit = calculate_vulnerability_priority(v_crit.id)
    res_high = calculate_vulnerability_priority(v_high.id)
    res_low = calculate_vulnerability_priority(v_low.id)

    assert res_crit['priority'] == 'CRITICAL'
    assert res_high['priority'] in ('HIGH', 'MEDIUM')
    assert res_low['priority'] == 'LOW'


def test_patch_priority_queue_sorting(app):
    v1 = create_vulnerability({'cve_id': 'CVE-LOW-99', 'software': 'LowSoft', 'vendor': 'V', 'cvss_score': 2.0, 'severity': 'LOW'})
    v2 = create_vulnerability({'cve_id': 'CVE-CRIT-99', 'software': 'CritSoft', 'vendor': 'V', 'cvss_score': 10.0, 'severity': 'CRITICAL', 'exploit_available': True, 'patch_available': True})

    queue = get_patch_priority_queue()
    assert len(queue) >= 2
    assert queue[0]['score'] >= queue[-1]['score']
    assert queue[0]['cve_id'] == 'CVE-CRIT-99'

def test_patch_priority_report_generation(app):
    create_vulnerability({'cve_id': 'CVE-REPORT-1', 'software': 'ReportSoft', 'vendor': 'V', 'cvss_score': 9.0, 'severity': 'CRITICAL'})

    # Data fetch test
    data = get_report_data(ReportType.PATCH_PRIORITY)
    assert "Patch Priority Queue" in data['title']
    assert len(data['headers']) == 9

    # CSV Generation test
    csv_str = generate_csv_report(ReportType.PATCH_PRIORITY)
    assert 'CVE-REPORT-1' in csv_str
    assert 'Patch Priority Queue' in csv_str

    # PDF Generation test
    pdf_bytes = generate_pdf_report(ReportType.PATCH_PRIORITY)
    assert pdf_bytes.startswith(b'%PDF')

def test_priority_score_nonexistent_vuln_raises_error(app):
    with pytest.raises(ValueError, match="not found"):
        calculate_vulnerability_priority(999999)

def test_priority_score_zero_assets_in_system(app):
    vuln = create_vulnerability({
        'cve_id': 'CVE-NOASSET',
        'software': 'IsolatedApp',
        'vendor': 'V',
        'cvss_score': 10.0,
        'severity': 'CRITICAL',
        'exploit_available': True,
        'patch_available': True
    })
    # 0 assets exist in DB
    p_data = calculate_vulnerability_priority(vuln.id)
    # CVSS (35) + Crit (0) + Exploit (15) + Assets (0) + Age (5) + Patch (5) = 60
    assert p_data['affected_assets_count'] == 0
    assert p_data['score'] == 60
    assert p_data['factor_points']['assets'] == 0.0
    assert p_data['factor_points']['criticality'] == 0.0

def test_priority_score_future_and_missing_published_dates(app):
    now_date = datetime.now(timezone.utc).date()

    # Future published date (days_old clamped to 0)
    future_date = now_date + timedelta(days=30)
    v_future = create_vulnerability({
        'cve_id': 'CVE-FUTURE',
        'software': 'FutureApp',
        'vendor': 'V',
        'cvss_score': 6.0,
        'severity': 'MEDIUM',
        'published_date': future_date
    })
    res_future = calculate_vulnerability_priority(v_future.id)
    assert res_future['factor_points']['age'] == 0.0

    # Missing published date (age_norm defaults to 0.5 -> 5.0 pts)
    v_nodate = create_vulnerability({
        'cve_id': 'CVE-NODATE',
        'software': 'NoDateApp',
        'vendor': 'V',
        'cvss_score': 6.0,
        'severity': 'MEDIUM',
        'published_date': None
    })
    res_nodate = calculate_vulnerability_priority(v_nodate.id)
    assert res_nodate['factor_points']['age'] == 5.0

