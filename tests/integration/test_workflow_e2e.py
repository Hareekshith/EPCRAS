import io
from datetime import datetime, date, timedelta, timezone
from epcras.models.user import Role
from epcras.models.asset import Asset, Department, Criticality
from epcras.models.software import Software, InstalledSoftware
from epcras.models.vulnerability import Vulnerability, Severity
from epcras.models.compliance import ComplianceResult, ComplianceStatus
from epcras.models.notification import Notification
from epcras.models.audit import AuditLog
from epcras.services.report_service import ReportType

def login(client, username, password):
    return client.post('/auth/login', data={
        'username_or_email': username,
        'password': password
    }, follow_redirects=True)

def test_full_enterprise_security_lifecycle_workflow(client, admin_user):
    """
    End-to-End Enterprise Workflow Integration Test:
    1. Administrator Authentication
    2. Department Creation
    3. Asset Provisioning (Critical Server & Low Workstation)
    4. Software Inventory Linking & Cataloguing
    5. Vulnerability Ingestion (Log4Shell & OpenSSL CVEs)
    6. Automated Organization-Wide Compliance Analysis
    7. Automated In-App Notifications Verification
    8. Patch Priority Queue Scoring and Ranking
    9. Dashboard Metric Calculations
    10. Multi-Format Report Generation (CSV & PDF)
    11. Immutable Audit Logging Verification
    """

    # 1. Administrator Authentication
    resp_login = login(client, admin_user.username, 'AdminSecret123!')
    assert resp_login.status_code == 200
    assert b"Welcome, admin_test" in resp_login.data

    # 2. Department Creation
    resp_dept = client.post('/assets/departments', data={
        'name': 'Core Infrastructure',
        'description': 'Mission critical datacenter operations'
    }, follow_redirects=True)
    assert resp_dept.status_code == 200
    assert b"Core Infrastructure" in resp_dept.data

    dept = Department.query.filter_by(name='Core Infrastructure').first()
    assert dept is not None

    # 3. Asset Provisioning via Web Routes
    # Asset 1: Critical Production Database Server
    resp_a1 = client.post('/assets/new', data={
        'hostname': 'PROD-DB-01',
        'ip_address': '10.50.1.10',
        'operating_system': 'Ubuntu Linux',
        'os_version': '22.04 LTS',
        'department_id': dept.id,
        'owner': 'Data Admin Team',
        'asset_type': 'Server',
        'criticality': Criticality.CRITICAL
    }, follow_redirects=True)
    assert resp_a1.status_code == 200
    assert b"PROD-DB-01" in resp_a1.data

    # Asset 2: Low-Risk Developer Workstation
    resp_a2 = client.post('/assets/new', data={
        'hostname': 'WS-DEV-01',
        'ip_address': '10.50.2.15',
        'operating_system': 'Ubuntu Linux',
        'os_version': '22.04 LTS',
        'department_id': dept.id,
        'owner': 'Dev Team',
        'asset_type': 'Workstation',
        'criticality': Criticality.LOW
    }, follow_redirects=True)
    assert resp_a2.status_code == 200
    assert b"WS-DEV-01" in resp_a2.data

    a1 = Asset.query.filter_by(hostname='PROD-DB-01').first()
    a2 = Asset.query.filter_by(hostname='WS-DEV-01').first()
    assert a1 is not None and a2 is not None

    # 4. Software Inventory Linking & Cataloguing
    # Add software to catalogue
    client.post('/software/new', data={'name': 'OpenSSL', 'vendor': 'OpenSSL Project', 'category': 'Cryptography'}, follow_redirects=True)
    client.post('/software/new', data={'name': 'curl', 'vendor': 'Haxx', 'category': 'Networking'}, follow_redirects=True)

    sw_openssl = Software.query.filter_by(name='OpenSSL').first()
    sw_curl = Software.query.filter_by(name='curl').first()
    assert sw_openssl is not None and sw_curl is not None

    # Link vulnerable OpenSSL 1.1.1f & curl 7.68.0 to PROD-DB-01
    client.post(f'/assets/{a1.id}/software/add', data={'software_id': sw_openssl.id, 'version': '1.1.1f'}, follow_redirects=True)
    client.post(f'/assets/{a1.id}/software/add', data={'software_id': sw_curl.id, 'version': '7.68.0'}, follow_redirects=True)

    # Link patched OpenSSL 1.1.1w to WS-DEV-01
    client.post(f'/assets/{a2.id}/software/add', data={'software_id': sw_openssl.id, 'version': '1.1.1w'}, follow_redirects=True)

    assert a1.installed_software.count() == 2
    assert a2.installed_software.count() == 1

    # 5. Vulnerability Ingestion
    past_date = (datetime.now(timezone.utc) - timedelta(days=200)).strftime('%Y-%m-%d')

    # Ingest CVE-2021-3711 for OpenSSL
    resp_v1 = client.post('/vulnerabilities/new', data={
        'cve_id': 'CVE-2021-3711',
        'software': 'OpenSSL',
        'vendor': 'OpenSSL Project',
        'description': 'SM4 decryption buffer overflow vulnerability',
        'cvss_score': '9.8',
        'severity': 'CRITICAL',
        'affected_versions': '< 1.1.1l',
        'fixed_version': '1.1.1l',
        'patch_available': 'y',
        'exploit_available': 'y',
        'published_date': past_date
    }, follow_redirects=True)
    assert resp_v1.status_code == 200
    assert b"CVE-2021-3711" in resp_v1.data

    # Ingest CVE-2023-38545 for curl
    resp_v2 = client.post('/vulnerabilities/new', data={
        'cve_id': 'CVE-2023-38545',
        'software': 'curl',
        'vendor': 'Haxx',
        'description': 'SOCKS5 heap buffer overflow',
        'cvss_score': '9.8',
        'severity': 'CRITICAL',
        'affected_versions': '< 8.4.0',
        'fixed_version': '8.4.0',
        'patch_available': 'y',
        'exploit_available': 'y',
        'published_date': past_date
    }, follow_redirects=True)
    assert resp_v2.status_code == 200
    assert b"CVE-2023-38545" in resp_v2.data

    # 6. Automated Organization-Wide Compliance Analysis
    resp_scan = client.post('/compliance/run', follow_redirects=True)
    assert resp_scan.status_code == 200
    assert b"Compliance analysis completed" in resp_scan.data

    # Verify database state after analysis
    # PROD-DB-01 software statuses
    inst_openssl_a1 = InstalledSoftware.query.filter_by(asset_id=a1.id, software_id=sw_openssl.id).first()
    inst_curl_a1 = InstalledSoftware.query.filter_by(asset_id=a1.id, software_id=sw_curl.id).first()
    assert inst_openssl_a1.compliance_status == 'Non-Compliant'
    assert inst_curl_a1.compliance_status == 'Non-Compliant'

    # WS-DEV-01 software status (patched version 1.1.1w >= 1.1.1l)
    inst_openssl_a2 = InstalledSoftware.query.filter_by(asset_id=a2.id, software_id=sw_openssl.id).first()
    assert inst_openssl_a2.compliance_status == 'Compliant'

    # Findings in ComplianceResult
    findings_a1 = ComplianceResult.query.filter_by(asset_id=a1.id, status=ComplianceStatus.NON_COMPLIANT).all()
    assert len(findings_a1) == 2
    cves_a1 = {f.cve_id for f in findings_a1}
    assert 'CVE-2021-3711' in cves_a1
    assert 'CVE-2023-38545' in cves_a1

    findings_a2 = ComplianceResult.query.filter_by(asset_id=a2.id, status=ComplianceStatus.NON_COMPLIANT).all()
    assert len(findings_a2) == 0

    # 7. Automated In-App Notifications Verification
    notifs = Notification.query.all()
    assert len(notifs) >= 3  # 2 critical vulns + 1 non-compliant asset notification
    assert any('PROD-DB-01' in n.title for n in notifs)
    assert any('CVE-2021-3711' in n.title for n in notifs)
    assert any('CVE-2023-38545' in n.title for n in notifs)

    # 8. Patch Priority Queue Evaluation
    resp_prio = client.get('/compliance/priority')
    assert resp_prio.status_code == 200
    assert b"Patch Priority Queue" in resp_prio.data
    assert b"CVE-2021-3711" in resp_prio.data
    assert b"CRITICAL" in resp_prio.data

    # 9. Dashboard Metric Calculations
    resp_dash = client.get('/dashboard')
    assert resp_dash.status_code == 200
    # 2 total assets, 1 compliant (50% rate)
    assert b"50" in resp_dash.data

    # 10. Multi-Format Report Generation (CSV & PDF)
    for rtype in [ReportType.OVERALL_COMPLIANCE, ReportType.CRITICAL_VULNERABILITY, ReportType.PATCH_PRIORITY]:
        # CSV Export
        resp_csv = client.get(f'/reports/export/{rtype}/csv')
        assert resp_csv.status_code == 200
        assert resp_csv.mimetype == 'text/csv'
        assert b"PROD-DB-01" in resp_csv.data or b"CVE-2021-3711" in resp_csv.data

        # PDF Export
        resp_pdf = client.get(f'/reports/export/{rtype}/pdf')
        assert resp_pdf.status_code == 200
        assert resp_pdf.mimetype == 'application/pdf'
        assert resp_pdf.data.startswith(b'%PDF')

    # 11. Immutable Audit Logging Verification
    audit_categories = [log.action_category for log in AuditLog.query.all()]
    assert 'AUTH' in audit_categories
    assert 'DEPARTMENT' in audit_categories
    assert 'ASSET_CREATED' in audit_categories
    assert 'SOFTWARE_UPDATED' in audit_categories
    assert 'VULN' in audit_categories
    assert 'COMPLIANCE_SCAN' in audit_categories
