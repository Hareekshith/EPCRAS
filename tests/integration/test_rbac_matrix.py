import pytest
from epcras.models.user import Role
from epcras.models.asset import Criticality
from epcras.services.asset_service import create_asset
from epcras.services.vulnerability_service import create_vulnerability

def login(client, user):
    password_map = {
        'admin_test': 'AdminSecret123!',
        'analyst_test': 'AnalystSecret123!',
        'support_test': 'SupportSecret123!',
        'auditor_test': 'AuditorSecret123!'
    }
    return client.post('/auth/login', data={
        'username_or_email': user.username,
        'password': password_map[user.username]
    }, follow_redirects=True)

def logout(client):
    return client.get('/auth/logout', follow_redirects=True)

@pytest.fixture
def test_asset(app):
    return create_asset({'hostname': 'RBAC-PC01', 'ip_address': '10.0.0.1', 'operating_system': 'Linux'})

@pytest.fixture
def test_vuln(app):
    return create_vulnerability({
        'cve_id': 'CVE-2024-RBAC',
        'software': 'RbacApp',
        'vendor': 'RbacVendor',
        'cvss_score': 7.5,
        'severity': 'HIGH'
    })

def test_rbac_admin_blueprint_matrix(client, admin_user, analyst_user, support_user, auditor_user):
    endpoints = ['/admin/', '/admin/users', '/admin/users/new', '/admin/audit-logs']

    # 1. Unauthenticated -> 302 redirect
    for ep in endpoints:
        resp = client.get(ep)
        assert resp.status_code in (302, 401)

    # 2. Administrator -> 200 OK
    login(client, admin_user)
    for ep in endpoints:
        assert client.get(ep).status_code == 200
    logout(client)

    # 3. Security Analyst -> 403 Forbidden
    login(client, analyst_user)
    for ep in endpoints:
        assert client.get(ep).status_code == 403
    logout(client)

    # 4. IT Support -> 403 Forbidden
    login(client, support_user)
    for ep in endpoints:
        assert client.get(ep).status_code == 403
    logout(client)

    # 5. Auditor -> 403 Forbidden
    login(client, auditor_user)
    for ep in endpoints:
        assert client.get(ep).status_code == 403
    logout(client)

def test_rbac_asset_read_write_matrix(client, admin_user, analyst_user, support_user, auditor_user, test_asset):
    read_endpoints = ['/assets/', f'/assets/{test_asset.id}']
    write_endpoints_get = ['/assets/new', f'/assets/{test_asset.id}/edit', '/assets/departments']

    # Read endpoints: all authenticated roles allowed (200 OK)
    for user in [admin_user, analyst_user, support_user, auditor_user]:
        login(client, user)
        for ep in read_endpoints:
            assert client.get(ep).status_code == 200
        logout(client)

    # Write endpoints GET: Admin and IT Support allowed (200 OK)
    for user in [admin_user, support_user]:
        login(client, user)
        for ep in write_endpoints_get:
            assert client.get(ep).status_code == 200
        logout(client)

    # Write endpoints GET: Analyst and Auditor forbidden (403)
    for user in [analyst_user, auditor_user]:
        login(client, user)
        for ep in write_endpoints_get:
            assert client.get(ep).status_code == 403
        # POST delete forbidden (403)
        assert client.post(f'/assets/{test_asset.id}/delete').status_code == 403
        logout(client)

def test_rbac_software_matrix(client, admin_user, analyst_user, support_user, auditor_user):
    # Read software: all authenticated roles allowed
    for user in [admin_user, analyst_user, support_user, auditor_user]:
        login(client, user)
        assert client.get('/software/').status_code == 200
        logout(client)

    # Write software: Admin and IT Support allowed
    for user in [admin_user, support_user]:
        login(client, user)
        assert client.get('/software/new').status_code == 200
        assert client.get('/software/import').status_code == 200
        logout(client)

    # Write software: Analyst and Auditor forbidden (403)
    for user in [analyst_user, auditor_user]:
        login(client, user)
        assert client.get('/software/new').status_code == 403
        assert client.get('/software/import').status_code == 403
        logout(client)

def test_rbac_vulnerability_matrix(client, admin_user, analyst_user, support_user, auditor_user, test_vuln):
    read_endpoints = ['/vulnerabilities/', f'/vulnerabilities/{test_vuln.id}']
    write_endpoints_get = ['/vulnerabilities/new', f'/vulnerabilities/{test_vuln.id}/edit', '/vulnerabilities/import']

    # Read: Admin and Analyst allowed (200 OK)
    for user in [admin_user, analyst_user]:
        login(client, user)
        for ep in read_endpoints:
            assert client.get(ep).status_code == 200
        logout(client)

    # Read: IT Support and Auditor forbidden (403)
    for user in [support_user, auditor_user]:
        login(client, user)
        for ep in read_endpoints:
            assert client.get(ep).status_code == 403
        logout(client)

    # Write: Admin ONLY allowed (200 OK)
    login(client, admin_user)
    for ep in write_endpoints_get:
        assert client.get(ep).status_code == 200
    logout(client)

    # Write: Analyst, IT Support, Auditor forbidden (403)
    for user in [analyst_user, support_user, auditor_user]:
        login(client, user)
        for ep in write_endpoints_get:
            assert client.get(ep).status_code == 403
        # POST delete forbidden (403)
        assert client.post(f'/vulnerabilities/{test_vuln.id}/delete').status_code == 403
        logout(client)

def test_rbac_compliance_analysis_run_matrix(client, admin_user, analyst_user, support_user, auditor_user, test_asset):
    # Read compliance: all authenticated roles allowed
    read_eps = ['/compliance/', '/compliance/non-compliant', f'/compliance/assets/{test_asset.id}', '/compliance/priority']
    for user in [admin_user, analyst_user, support_user, auditor_user]:
        login(client, user)
        for ep in read_eps:
            assert client.get(ep).status_code == 200
        logout(client)

    # Run analysis (POST /compliance/run): Admin, Analyst, IT Support allowed (302 redirect after running)
    for user in [admin_user, analyst_user, support_user]:
        login(client, user)
        resp = client.post('/compliance/run', follow_redirects=False)
        assert resp.status_code == 302
        logout(client)

    # Run analysis: Auditor forbidden (403)
    login(client, auditor_user)
    resp = client.post('/compliance/run')
    assert resp.status_code == 403
    logout(client)

def test_rbac_reports_matrix(client, admin_user, analyst_user, support_user, auditor_user):
    # All authenticated roles can view and export reports
    for user in [admin_user, analyst_user, support_user, auditor_user]:
        login(client, user)
        assert client.get('/reports/').status_code == 200
        assert client.get('/reports/export/OVERALL_COMPLIANCE/csv').status_code == 200
        logout(client)
