from epcras.models.compliance import ComplianceResult, ComplianceStatus
from epcras.services.asset_service import create_asset
from epcras.services.software_service import get_or_create_software, add_installed_software
from epcras.services.vulnerability_service import create_vulnerability

def login_as(client, username, password):
    return client.post('/auth/login', data={
        'username_or_email': username,
        'password': password
    }, follow_redirects=True)

def test_compliance_overview_route_auth(client, analyst_user):
    # Unauthenticated
    resp = client.get('/compliance/')
    assert resp.status_code in (302, 401)

    # Authenticated Analyst
    login_as(client, analyst_user.username, 'AnalystSecret123!')
    resp = client.get('/compliance/')
    assert resp.status_code == 200
    assert b'Patch Compliance Overview' in resp.data

def test_run_compliance_analysis_route(client, admin_user, app):
    asset = create_asset({'hostname': 'SRV-TEST-01', 'ip_address': '10.10.10.1'})
    sw = get_or_create_software("Log4j", "Apache")
    add_installed_software(asset.id, sw.id, "2.14.0")

    create_vulnerability({
        'cve_id': 'CVE-2021-44228',
        'software': 'Log4j',
        'vendor': 'Apache',
        'cvss_score': 10.0,
        'severity': 'CRITICAL',
        'affected_versions': '2.0 <= 2.14.1',
        'fixed_version': '2.17.1'
    })

    login_as(client, admin_user.username, 'AdminSecret123!')

    resp = client.post('/compliance/run', follow_redirects=True)
    assert resp.status_code == 200
    assert b'Compliance analysis completed' in resp.data

    findings = ComplianceResult.query.filter_by(status=ComplianceStatus.NON_COMPLIANT).all()
    assert len(findings) >= 1

def test_non_compliant_route(client, analyst_user, app):
    login_as(client, analyst_user.username, 'AnalystSecret123!')

    resp = client.get('/compliance/non-compliant')
    assert resp.status_code == 200
    assert b'Non-Compliant Vulnerability Exposure' in resp.data

def test_asset_compliance_detail_route(client, analyst_user, app):
    asset = create_asset({'hostname': 'SRV-TEST-02', 'ip_address': '10.10.10.2'})
    login_as(client, analyst_user.username, 'AnalystSecret123!')

    resp = client.get(f'/compliance/assets/{asset.id}')
    assert resp.status_code == 200
    assert b'SRV-TEST-02' in resp.data

    # Nonexistent asset
    resp_none = client.get('/compliance/assets/999999', follow_redirects=True)
    assert resp_none.status_code == 200
    assert b"Asset not found" in resp_none.data

def test_targeted_compliance_run_and_filtering_routes(client, admin_user, app):
    asset = create_asset({'hostname': 'SRV-TARGET-99', 'ip_address': '10.10.10.99'})
    login_as(client, admin_user.username, 'AdminSecret123!')

    # Targeted run for single asset
    resp = client.post('/compliance/run', data={'asset_id': str(asset.id)}, follow_redirects=True)
    assert resp.status_code == 200
    assert b'Compliance analysis completed' in resp.data

    # Filter non-compliant route
    resp_filter = client.get('/compliance/non-compliant?severity=CRITICAL&software=Log4j')
    assert resp_filter.status_code == 200


def test_manual_update_finding_route(client, admin_user, app):
    from epcras.services.compliance_service import run_compliance_analysis

    asset = create_asset({'hostname': 'SRV-PATCH-DEMO', 'ip_address': '10.10.20.1'})
    sw = get_or_create_software("Apache HTTP Server", "Apache Software Foundation")
    add_installed_software(asset.id, sw.id, "2.4.49")

    create_vulnerability({
        'cve_id': 'CVE-2021-41773',
        'software': 'Apache HTTP Server',
        'vendor': 'Apache Software Foundation',
        'cvss_score': 9.8,
        'severity': 'CRITICAL',
        'affected_versions': '2.4.49',
        'fixed_version': '2.4.51'
    })

    run_compliance_analysis(asset_id=asset.id)
    finding = ComplianceResult.query.filter_by(asset_id=asset.id, status=ComplianceStatus.NON_COMPLIANT).first()
    assert finding is not None

    login_as(client, admin_user.username, 'AdminSecret123!')

    # Post manual update to fixed version
    resp = client.post(f'/compliance/findings/{finding.id}/update', data={
        'target_version': '2.4.51'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b'as updated to version 2.4.51' in resp.data

    # Ensure finding is removed from non-compliant findings
    remaining = ComplianceResult.query.filter_by(asset_id=asset.id, status=ComplianceStatus.NON_COMPLIANT).all()
    assert len(remaining) == 0


def test_bulk_patch_route(client, support_user, app):
    from epcras.services.compliance_service import run_compliance_analysis

    a1 = create_asset({'hostname': 'BULK-ROUTE-01', 'ip_address': '10.10.30.1'})
    a2 = create_asset({'hostname': 'BULK-ROUTE-02', 'ip_address': '10.10.30.2'})
    sw = get_or_create_software("Tomcat", "Apache Software Foundation")
    add_installed_software(a1.id, sw.id, "9.0.40")
    add_installed_software(a2.id, sw.id, "9.0.40")

    create_vulnerability({
        'cve_id': 'CVE-2021-25122',
        'software': 'Tomcat',
        'vendor': 'Apache Software Foundation',
        'cvss_score': 7.5,
        'severity': 'HIGH',
        'affected_versions': '9.0.40',
        'fixed_version': '9.0.43'
    })

    run_compliance_analysis()
    findings = ComplianceResult.query.filter_by(cve_id='CVE-2021-25122', status=ComplianceStatus.NON_COMPLIANT).all()
    assert len(findings) >= 2

    login_as(client, support_user.username, 'SupportSecret123!')

    # Execute bulk patch for all fixable
    resp = client.post('/compliance/bulk-update', data={
        'patch_all_fixable': 'true'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b'Bulk patch successful' in resp.data

    # Verify both are resolved
    remaining = ComplianceResult.query.filter_by(cve_id='CVE-2021-25122', status=ComplianceStatus.NON_COMPLIANT).all()
    assert len(remaining) == 0


