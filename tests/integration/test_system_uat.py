import io
from epcras.models.user import User, Role
from epcras.models.asset import Asset, Department, Criticality
from epcras.models.software import Software, InstalledSoftware
from epcras.models.vulnerability import Vulnerability, Severity
from epcras.models.compliance import ComplianceResult, ComplianceStatus
from epcras.models.notification import Notification
from epcras.models.audit import AuditLog
from epcras.services.report_service import ReportType

def login_client(client, username, password):
    return client.post('/auth/login', data={
        'username_or_email': username,
        'password': password
    }, follow_redirects=True)

def logout_client(client):
    return client.get('/auth/logout', follow_redirects=True)

def test_system_uat_administrator_workflow(client, admin_user):
    """
    Automated System Check: Administrator End-to-End Workflow
    - Login
    - User Management (Create, Edit, Toggle Status)
    - Department & Asset Registration
    - Software Catalogue & CSV Ingestion
    - Vulnerability CRUD & CSV Ingestion
    - Run Compliance Analysis
    - Identify Non-Compliant Assets
    - View Dashboard & Patch Priority
    - Centralized Search
    - In-App Notifications
    - Report Generation (PDF & CSV)
    - Audit Trail Verification
    """
    # 1. Login
    resp = login_client(client, admin_user.username, 'AdminSecret123!')
    assert resp.status_code == 200
    assert b"Welcome, admin_test" in resp.data

    # 2. Administrator User Management
    # 2a. Create a new user account
    resp_create_user = client.post('/admin/users/new', data={
        'username': 'sec_officer',
        'email': 'officer@example.com',
        'password': 'SecureOfficerPass123!',
        'role': Role.SECURITY_ANALYST,
        'is_active': 'y'
    }, follow_redirects=True)
    assert resp_create_user.status_code == 200
    assert b"created successfully" in resp_create_user.data
    assert b"sec_officer" in resp_create_user.data
    new_user = User.query.filter_by(username='sec_officer').first()
    assert new_user is not None

    # 2b. Edit user account
    resp_edit_user = client.post(f'/admin/users/{new_user.id}/edit', data={
        'email': 'officer_updated@example.com',
        'role': Role.SECURITY_ANALYST,
        'is_active': 'y',
        'password': ''
    }, follow_redirects=True)
    assert resp_edit_user.status_code == 200
    assert b"updated successfully" in resp_edit_user.data
    assert new_user.email == 'officer_updated@example.com'

    # 2c. Toggle user status (disable)
    resp_toggle = client.post(f'/admin/users/{new_user.id}/toggle-status', follow_redirects=True)
    assert resp_toggle.status_code == 200
    assert b"User account has been disabled." in resp_toggle.data
    assert new_user.is_active is False

    # 2d. Prevent admin self-disable
    resp_self_toggle = client.post(f'/admin/users/{admin_user.id}/toggle-status', follow_redirects=True)
    assert resp_self_toggle.status_code == 200
    assert b"You cannot disable your own active administrator account." in resp_self_toggle.data
    assert admin_user.is_active is True

    # 3. Department & Asset Registration
    resp_dept = client.post('/assets/departments', data={
        'name': 'Corporate Banking',
        'description': 'Core financial infrastructure'
    }, follow_redirects=True)
    assert resp_dept.status_code == 200
    dept = Department.query.filter_by(name='Corporate Banking').first()
    assert dept is not None

    resp_asset = client.post('/assets/new', data={
        'hostname': 'BANK-PROD-APP01',
        'ip_address': '10.10.40.10',
        'operating_system': 'Red Hat Enterprise Linux',
        'os_version': '9.2',
        'department_id': dept.id,
        'owner': 'FinOps Team',
        'asset_type': 'Server',
        'criticality': Criticality.CRITICAL
    }, follow_redirects=True)
    assert resp_asset.status_code == 200
    asset = Asset.query.filter_by(hostname='BANK-PROD-APP01').first()
    assert asset is not None

    # 4. Software Catalogue & CSV Ingestion
    # 4a. Manual software creation
    resp_sw_cat = client.post('/software/new', data={
        'name': 'Apache HTTP Server',
        'vendor': 'Apache Software Foundation',
        'category': 'Web Server'
    }, follow_redirects=True)
    assert resp_sw_cat.status_code == 200
    apache_sw = Software.query.filter_by(name='Apache HTTP Server').first()
    assert apache_sw is not None

    # 4b. CSV software import
    csv_software_data = (
        "hostname,software,version,vendor,category\n"
        "BANK-PROD-APP01,PostgreSQL,13.2,PostgreSQL Global Development Group,Database\n"
        "BANK-PROD-APP01,OpenSSL,1.1.1d,OpenSSL Project,Cryptography\n"
    )
    resp_sw_csv = client.post('/software/import', data={
        'csv_file': (io.BytesIO(csv_software_data.encode('utf-8')), 'software_inventory.csv')
    }, follow_redirects=True)
    assert resp_sw_csv.status_code == 200
    assert b"Successfully imported 2 software inventory records." in resp_sw_csv.data
    assert asset.installed_software.count() == 2

    # 5. Vulnerability CRUD & CSV Ingestion
    # 5a. Manual vulnerability creation
    resp_vuln_create = client.post('/vulnerabilities/new', data={
        'cve_id': 'CVE-2021-3711',
        'software': 'OpenSSL',
        'vendor': 'OpenSSL Project',
        'description': 'SM2 Decryption Buffer Overflow',
        'cvss_score': 9.8,
        'severity': Severity.CRITICAL,
        'affected_versions': '< 1.1.1l',
        'fixed_version': '1.1.1l',
        'patch_available': True,
        'exploit_available': True,
        'published_date': '2021-08-24'
    }, follow_redirects=True)
    assert resp_vuln_create.status_code == 200
    vuln1 = Vulnerability.query.filter_by(cve_id='CVE-2021-3711').first()
    assert vuln1 is not None

    # 5b. Vulnerability CSV Ingestion
    csv_vuln_data = (
        "cve_id,software,vendor,description,cvss_score,severity,affected_versions,fixed_version,patch_available,exploit_available,published_date\n"
        "CVE-2021-3156,PostgreSQL,PostgreSQL Global Development Group,Buffer overflow issue,7.8,HIGH,< 13.3,13.3,true,false,2021-05-13\n"
    )
    resp_vuln_csv = client.post('/vulnerabilities/import', data={
        'csv_file': (io.BytesIO(csv_vuln_data.encode('utf-8')), 'cves.csv')
    }, follow_redirects=True)
    assert resp_vuln_csv.status_code == 200
    assert b"Successfully imported 1 vulnerability records." in resp_vuln_csv.data

    # 6. Run Compliance Analysis
    resp_comp_run = client.post('/compliance/run', follow_redirects=True)
    assert resp_comp_run.status_code == 200
    assert b"Compliance analysis completed." in resp_comp_run.data
    assert b"non-compliant vulnerability finding(s)" in resp_comp_run.data

    # 7. Identify Non-Compliant Asset
    resp_non_comp = client.get('/compliance/non-compliant')
    assert resp_non_comp.status_code == 200
    assert b"BANK-PROD-APP01" in resp_non_comp.data
    assert b"CVE-2021-3711" in resp_non_comp.data

    # 8. View Dashboard & Patch Priority
    resp_dash = client.get('/dashboard')
    assert resp_dash.status_code == 200
    assert b"Total IT Assets" in resp_dash.data

    resp_prio = client.get('/compliance/priority')
    assert resp_prio.status_code == 200
    assert b"Patch Priority Queue" in resp_prio.data
    assert b"CVE-2021-3711" in resp_prio.data

    # 9. Search Records
    resp_search = client.get('/search/?hostname=BANK-PROD-APP01&severity=CRITICAL')
    assert resp_search.status_code == 200
    assert b"BANK-PROD-APP01" in resp_search.data

    # 10. View Notifications & Mark As Read
    resp_notifs = client.get('/notifications/')
    assert resp_notifs.status_code == 200
    assert b"Notifications" in resp_notifs.data

    resp_mark_all = client.post('/notifications/read-all', follow_redirects=True)
    assert resp_mark_all.status_code == 200

    # 11. Generate PDF & CSV Reports
    resp_pdf = client.get(f'/reports/export/{ReportType.OVERALL_COMPLIANCE}/pdf')
    assert resp_pdf.status_code == 200
    assert resp_pdf.mimetype == 'application/pdf'
    assert len(resp_pdf.data) > 0

    resp_csv = client.get(f'/reports/export/{ReportType.PATCH_PRIORITY}/csv')
    assert resp_csv.status_code == 200
    assert resp_csv.mimetype == 'text/csv'
    assert b"CVE ID,Software Name" in resp_csv.data

    # 12. Audit Log Verification
    resp_audit = client.get('/admin/audit-logs')
    assert resp_audit.status_code == 200
    assert b"Audit Log Viewer" in resp_audit.data
    assert b"COMPLIANCE_SCAN" in resp_audit.data

def test_system_uat_security_analyst_workflow(client, analyst_user, admin_user):
    """
    Automated System Check: Security Analyst Workflow
    - Login
    - View Dashboard Posture
    - Browse Vulnerabilities & View CVE Detail
    - Run Organization & Targeted Compliance Scans
    - Filter Non-Compliant Assets by Severity and Software
    - Inspect Patch Priority Queue & Scores
    - Perform Multi-Parameter Search
    - Generate Executive & Risk Reports (PDF & CSV)
    - Notification Management
    - Enforce RBAC (Cannot access admin users or modify assets/vulnerabilities)
    """
    # Setup data as admin first
    login_client(client, admin_user.username, 'AdminSecret123!')
    dept = Department(name='SecOps Testing', description='Security Testing Dept')
    asset = Asset(
        hostname='SEC-ANALYST-SRV',
        ip_address='192.168.10.5',
        operating_system='Debian GNU/Linux',
        os_version='12',
        criticality=Criticality.HIGH
    )
    sw = Software(name='sudo', vendor='Sudo Team', category='System')
    vuln = Vulnerability(
        cve_id='CVE-2021-3156',
        software='sudo',
        vendor='Sudo Team',
        description='Baron Samedit Heap-based buffer overflow',
        cvss_score=7.8,
        severity=Severity.HIGH,
        affected_versions='< 1.9.5',
        fixed_version='1.9.5',
        patch_available=True,
        exploit_available=True
    )
    from epcras.extensions import db
    db.session.add_all([dept, asset, sw, vuln])
    db.session.commit()
    inst = InstalledSoftware(asset_id=asset.id, software_id=sw.id, version='1.8.27')
    db.session.add(inst)
    db.session.commit()
    logout_client(client)

    # 1. Login as Security Analyst
    resp_login = login_client(client, analyst_user.username, 'AnalystSecret123!')
    assert resp_login.status_code == 200
    assert b"Welcome, analyst_test" in resp_login.data

    # 2. View Dashboard
    resp_dash = client.get('/dashboard')
    assert resp_dash.status_code == 200
    assert b"Compliance Rate" in resp_dash.data

    # 3. Browse Vulnerabilities & View Detail
    resp_vulns = client.get('/vulnerabilities/')
    assert resp_vulns.status_code == 200
    assert b"CVE-2021-3156" in resp_vulns.data

    resp_vdetail = client.get(f'/vulnerabilities/{vuln.id}')
    assert resp_vdetail.status_code == 200
    assert b"Baron Samedit" in resp_vdetail.data

    # 4. Run Compliance Scan
    resp_scan = client.post('/compliance/run', follow_redirects=True)
    assert resp_scan.status_code == 200
    assert b"Compliance analysis completed." in resp_scan.data

    # 5. Filter Non-Compliant Assets
    resp_noncomp = client.get('/compliance/non-compliant?severity=HIGH&software=sudo')
    assert resp_noncomp.status_code == 200
    assert b"SEC-ANALYST-SRV" in resp_noncomp.data
    assert b"CVE-2021-3156" in resp_noncomp.data

    # 6. View Asset Compliance Detail
    resp_adetail = client.get(f'/compliance/assets/{asset.id}')
    assert resp_adetail.status_code == 200
    assert b"SEC-ANALYST-SRV" in resp_adetail.data

    # 7. View Patch Priority Queue
    resp_prio = client.get('/compliance/priority')
    assert resp_prio.status_code == 200
    assert b"CVE-2021-3156" in resp_prio.data

    # 8. Search Records
    resp_search = client.get('/search/?software=sudo&compliance_status=Non-Compliant')
    assert resp_search.status_code == 200
    assert b"SEC-ANALYST-SRV" in resp_search.data

    # 9. Reports Generation
    resp_pdf = client.get(f'/reports/export/{ReportType.CRITICAL_VULNERABILITY}/pdf')
    assert resp_pdf.status_code == 200
    assert resp_pdf.mimetype == 'application/pdf'

    resp_csv = client.get(f'/reports/export/{ReportType.CRITICAL_VULNERABILITY}/csv')
    assert resp_csv.status_code == 200
    assert resp_csv.mimetype == 'text/csv'

    # 10. Enforce RBAC Restrictions for Analyst
    # Analyst cannot create users
    resp_admin = client.get('/admin/users')
    assert resp_admin.status_code == 403

    # Analyst cannot access audit logs
    resp_audit = client.get('/admin/audit-logs')
    assert resp_audit.status_code == 403

    # Analyst cannot create new asset
    resp_asset_new = client.get('/assets/new')
    assert resp_asset_new.status_code == 403

    # Analyst cannot create vulnerability
    resp_vuln_new = client.get('/vulnerabilities/new')
    assert resp_vuln_new.status_code == 403

def test_system_uat_it_support_workflow(client, support_user, admin_user):
    """
    Automated System Check: IT Support Workflow
    - Login
    - Create Department
    - Register IT Asset
    - Add Software to Catalogue
    - Associate Software Version with Asset
    - Run Targeted Compliance Scan
    - View Asset Compliance & Remediation Status
    - View Patch Priority Queue
    - Search Assets & Inventory
    - Export Asset Compliance Report (CSV & PDF)
    - Enforce RBAC (Cannot access admin users, audit logs, or edit vulnerabilities)
    """
    # 1. Login as IT Support
    resp_login = login_client(client, support_user.username, 'SupportSecret123!')
    assert resp_login.status_code == 200
    assert b"Welcome, support_test" in resp_login.data

    # 2. Create Department
    resp_dept = client.post('/assets/departments', data={
        'name': 'Customer Care Helpdesk',
        'description': 'IT Support and customer operations'
    }, follow_redirects=True)
    assert resp_dept.status_code == 200
    dept = Department.query.filter_by(name='Customer Care Helpdesk').first()
    assert dept is not None

    # 3. Register IT Asset
    resp_asset = client.post('/assets/new', data={
        'hostname': 'HELPDESK-WS-12',
        'ip_address': '172.16.5.12',
        'operating_system': 'Windows 11 Enterprise',
        'os_version': '23H2',
        'department_id': dept.id,
        'owner': 'Jane Doe',
        'asset_type': 'Workstation',
        'criticality': Criticality.MEDIUM
    }, follow_redirects=True)
    assert resp_asset.status_code == 200
    asset = Asset.query.filter_by(hostname='HELPDESK-WS-12').first()
    assert asset is not None

    # 4. Add Software to Catalogue
    resp_sw = client.post('/software/new', data={
        'name': 'Mozilla Firefox',
        'vendor': 'Mozilla',
        'category': 'Web Browser'
    }, follow_redirects=True)
    assert resp_sw.status_code == 200
    sw = Software.query.filter_by(name='Mozilla Firefox').first()
    assert sw is not None

    # 5. Associate Software with Asset
    resp_link = client.post(f'/assets/{asset.id}/software/add', data={
        'software_id': sw.id,
        'version': '115.0'
    }, follow_redirects=True)
    assert resp_link.status_code == 200
    assert b"Installed software linked successfully." in resp_link.data

    # 6. Run Targeted Asset Compliance Scan
    resp_scan = client.post(f'/compliance/run', data={'asset_id': str(asset.id)}, follow_redirects=True)
    assert resp_scan.status_code == 200
    assert b"Compliance analysis completed." in resp_scan.data

    # 7. View Asset Compliance Detail
    resp_detail = client.get(f'/compliance/assets/{asset.id}')
    assert resp_detail.status_code == 200
    assert b"HELPDESK-WS-12" in resp_detail.data

    # 8. View Patch Priority Queue
    resp_prio = client.get('/compliance/priority')
    assert resp_prio.status_code == 200
    assert b"Patch Priority Queue" in resp_prio.data

    # 9. Search Inventory
    resp_search = client.get('/search/?hostname=HELPDESK-WS-12')
    assert resp_search.status_code == 200
    assert b"HELPDESK-WS-12" in resp_search.data

    # 10. Generate Asset Compliance Report
    resp_csv = client.get(f'/reports/export/{ReportType.ASSET_COMPLIANCE}/csv')
    assert resp_csv.status_code == 200
    assert resp_csv.mimetype == 'text/csv'

    resp_pdf = client.get(f'/reports/export/{ReportType.ASSET_COMPLIANCE}/pdf')
    assert resp_pdf.status_code == 200
    assert resp_pdf.mimetype == 'application/pdf'

    # 11. Enforce RBAC Restrictions for IT Support
    # IT Support cannot access User Management
    resp_admin = client.get('/admin/users')
    assert resp_admin.status_code == 403

    # IT Support cannot access Audit Logs
    resp_audit = client.get('/admin/audit-logs')
    assert resp_audit.status_code == 403

    # IT Support cannot create or import Vulnerabilities
    resp_vuln_create = client.get('/vulnerabilities/new')
    assert resp_vuln_create.status_code == 403

    resp_vuln_import = client.get('/vulnerabilities/import')
    assert resp_vuln_import.status_code == 403
