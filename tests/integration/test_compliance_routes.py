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

