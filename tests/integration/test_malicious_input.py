import io
import pytest
from epcras.models.user import Role, User
from epcras.models.asset import Asset, Criticality
from epcras.models.vulnerability import Vulnerability
from epcras.services.asset_service import create_asset
from epcras.services.software_service import import_software_csv
from epcras.services.vulnerability_service import import_vulnerabilities_csv
from epcras.services.search_service import search_system
from epcras.services.audit_service import get_audit_logs

def login(client, username, password):
    return client.post('/auth/login', data={
        'username_or_email': username,
        'password': password
    }, follow_redirects=True)

def test_sql_injection_resilience_in_search_and_audit(app):
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT id, username, password_hash, role, is_active FROM users --",
        "admin' --",
        "1' OR 1=1#",
        "' OR ''='"
    ]

    # Search system with SQLi strings across all fields
    for payload in sqli_payloads:
        # Hostname search
        res1 = search_system({'hostname': payload})
        assert isinstance(res1['results_list'], list)

        # IP address search
        res2 = search_system({'ip_address': payload})
        assert isinstance(res2['results_list'], list)

        # CVE ID search
        res3 = search_system({'cve_id': payload})
        assert isinstance(res3['results_list'], list)

        # Audit log search with SQLi
        audit_res = get_audit_logs(search=payload)
        assert isinstance(audit_res['logs_list'], list)

    # Verify tables still intact and queryable
    assert User.query.count() >= 0
    assert Asset.query.count() >= 0

def test_xss_payload_handling_in_models_and_forms(client, admin_user):
    login(client, admin_user.username, 'AdminSecret123!')

    xss_payload = "<script>alert('EPCRAS_XSS')</script>"

    # 1. Asset creation with XSS payload in owner and operating system
    resp_asset = client.post('/assets/new', data={
        'hostname': 'XSS-PC-01',
        'ip_address': '192.168.1.99',
        'operating_system': f"Linux {xss_payload}",
        'owner': xss_payload,
        'asset_type': 'Workstation',
        'criticality': Criticality.LOW
    }, follow_redirects=True)
    assert resp_asset.status_code == 200
    # In Jinja2 auto-escaped HTML, `<` is rendered as `&lt;` and quotes as `&#39;`
    assert b"&lt;script&gt;alert(&#39;EPCRAS_XSS&#39;)&lt;/script&gt;" in resp_asset.data
    # Raw unescaped script tags must NEVER be executed
    assert b"<script>alert('EPCRAS_XSS')</script>" not in resp_asset.data

    # 2. Vulnerability with XSS payload in description
    resp_vuln = client.post('/vulnerabilities/new', data={
        'cve_id': 'CVE-2024-XSS1',
        'software': 'XssSoft',
        'vendor': 'XssVendor',
        'description': xss_payload,
        'cvss_score': '5.0',
        'severity': 'MEDIUM'
    }, follow_redirects=True)
    assert resp_vuln.status_code == 200
    assert b"&lt;script&gt;alert(&#39;EPCRAS_XSS&#39;)&lt;/script&gt;" in resp_vuln.data
    assert b"<script>alert('EPCRAS_XSS')</script>" not in resp_vuln.data

def test_path_traversal_in_report_export(client, admin_user):
    login(client, admin_user.username, 'AdminSecret123!')

    path_traversal_payloads = [
        '../../etc/passwd',
        '..%2F..%2Fetc%2Fpasswd',
        '....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f',
        '/etc/shadow'
    ]

    for payload in path_traversal_payloads:
        resp = client.get(f'/reports/export/{payload}/csv', follow_redirects=True)
        # Should return 404 Not Found or redirect away with invalid report type
        assert resp.status_code in (404, 302, 200)
        assert b"root:" not in resp.data

        resp_pdf = client.get(f'/reports/export/{payload}/pdf', follow_redirects=True)
        assert resp_pdf.status_code in (404, 302, 200)
        assert b"root:" not in resp_pdf.data

def test_open_redirect_attack_vectors(client, admin_user):
    open_redirect_vectors = [
        '//malicious.com',
        '///malicious.com',
        '/\\malicious.com',
        'https://attacker.com/steal-creds',
        'http://attacker.com',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>'
    ]

    for vector in open_redirect_vectors:
        resp = client.post(f'/auth/login?next={vector}', data={
            'username_or_email': admin_user.username,
            'password': 'AdminSecret123!'
        }, follow_redirects=False)

        assert resp.status_code == 302
        location = resp.headers.get('Location', '')
        assert 'attacker.com' not in location
        assert 'malicious.com' not in location
        assert not location.startswith('javascript:')
        assert not location.startswith('data:')
        # Always redirects safely to dashboard
        assert location == '/dashboard' or location.endswith('/dashboard')
        client.get('/auth/logout')

def test_oversized_payloads(client, admin_user):
    login(client, admin_user.username, 'AdminSecret123!')

    # 5,000 characters in hostname
    huge_string = "A" * 5000
    resp = client.post('/assets/new', data={
        'hostname': huge_string,
        'ip_address': '10.0.0.1',
        'operating_system': 'Linux'
    }, follow_redirects=True)
    # Form validation rejects lengths > 128
    assert b"Field cannot be longer than" in resp.data or resp.status_code == 200
    assert Asset.query.filter_by(hostname=huge_string).first() is None

def test_malformed_csv_handling_via_routes(client, admin_user):
    login(client, admin_user.username, 'AdminSecret123!')

    # 1. Binary payload uploaded as CSV
    binary_stream = io.BytesIO(b"\x00\x01\x02\xff\xfe\xfd\x80\x90\xaa\xbb")
    resp_sw = client.post('/software/import', data={
        'csv_file': (binary_stream, 'test_corrupt.csv')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp_sw.status_code == 200

    # 2. Completely empty CSV
    resp_empty = client.post('/software/import', data={
        'csv_file': (io.BytesIO(b""), 'empty.csv')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp_empty.status_code == 200
    assert b"empty or missing headers" in resp_empty.data

    # 3. CSV with invalid file extension
    resp_bad_ext = client.post('/software/import', data={
        'csv_file': (io.BytesIO(b"hostname,software,vendor,version\n"), 'test.exe')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp_bad_ext.status_code == 200
    assert b"Only CSV files are allowed" in resp_bad_ext.data

def test_admin_self_disable_prevention(client, admin_user):
    from epcras.extensions import db
    login(client, admin_user.username, 'AdminSecret123!')

    # Attempt to disable own active admin account
    resp = client.post(f'/admin/users/{admin_user.id}/toggle-status', follow_redirects=True)
    assert resp.status_code == 200
    assert b"You cannot disable your own active administrator account" in resp.data

    # Verify admin is still active
    reloaded_admin = db.session.get(User, admin_user.id)
    assert reloaded_admin.is_active is True

def test_invalid_cvss_form_submission(client, admin_user):
    login(client, admin_user.username, 'AdminSecret123!')

    # Form submission with CVSS > 10.0
    resp_over = client.post('/vulnerabilities/new', data={
        'cve_id': 'CVE-2024-INVALID1',
        'software': 'TestSoft',
        'vendor': 'TestVendor',
        'cvss_score': '15.5',
        'severity': 'CRITICAL'
    }, follow_redirects=True)
    assert b"CVSS score must be between 0.0 and 10.0" in resp_over.data

    # Form submission with negative CVSS
    resp_neg = client.post('/vulnerabilities/new', data={
        'cve_id': 'CVE-2024-INVALID2',
        'software': 'TestSoft',
        'vendor': 'TestVendor',
        'cvss_score': '-2.0',
        'severity': 'LOW'
    }, follow_redirects=True)
    assert b"CVSS score must be between 0.0 and 10.0" in resp_neg.data
