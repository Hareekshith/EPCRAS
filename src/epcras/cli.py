import os
from datetime import date
import click
from flask.cli import AppGroup
from epcras.extensions import db
from epcras.models.user import User, Role
from epcras.models.vulnerability import Vulnerability, Severity
from epcras.services.audit_service import log_audit_event

admin_cli = AppGroup('admin', help='Administrative CLI commands.')

@click.command('seed-admin')
@click.option('--username', default=lambda: os.environ.get('ADMIN_USERNAME', 'admin'), help='Admin username (default: admin)')
@click.option('--email', default=lambda: os.environ.get('ADMIN_EMAIL', 'admin@epcras.local'), help='Admin email (default: admin@epcras.local)')
@click.option('--password', default=lambda: os.environ.get('ADMIN_PASSWORD', None), help='Admin password (env: ADMIN_PASSWORD)')
def seed_admin_command(username, email, password):
    """Seed or update the administrator user."""
    if not password:
        import secrets
        try:
            password = click.prompt('Admin Password', hide_input=True, confirmation_prompt=True)
        except Exception:
            password = secrets.token_urlsafe(16)
            click.echo(f"Generated temporary administrator password: {password}")
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        existing_user.set_password(password)
        existing_user.is_active = True
        db.session.commit()
        click.echo(f"Successfully updated password for administrator user '{existing_user.username}'.")
        return

    admin_user = User(
        username=username,
        email=email,
        role=Role.ADMINISTRATOR,
        is_active=True
    )
    admin_user.set_password(password)
    db.session.add(admin_user)
    db.session.commit()


    log_audit_event(
        action_category='USER_MGMT',
        username='CLI_SEED',
        target_entity=f"User:{username}",
        details=f"Initial administrator account '{username}' created via CLI",
        status='SUCCESS'
    )
    click.echo(f"Successfully created administrator user '{username}' ({email}).")

@click.command('seed-vulnerabilities')
def seed_vulnerabilities_command():
    """Seed development vulnerability records (accurately sourced CVEs & clearly marked DEMO records)."""
    db.create_all()
    records = [

        {
            'cve_id': 'CVE-2021-44228',
            'software': 'Log4j',
            'vendor': 'Apache Software Foundation',
            'description': 'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
            'cvss_score': 10.0,
            'severity': Severity.CRITICAL,
            'affected_versions': '2.0-beta9 <= 2.14.1',
            'fixed_version': '2.17.1',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2021, 12, 10)
        },
        {
            'cve_id': 'CVE-2024-3094',
            'software': 'xz-utils',
            'vendor': 'Tukaani',
            'description': 'Malicious code in XZ Utils versions 5.6.0 and 5.6.1 allows unauthorized access via OpenSSH server functions.',
            'cvss_score': 10.0,
            'severity': Severity.CRITICAL,
            'affected_versions': '5.6.0, 5.6.1',
            'fixed_version': '5.6.2',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2024, 3, 29)
        },
        {
            'cve_id': 'CVE-2023-4863',
            'software': 'libwebp',
            'vendor': 'Google',
            'description': 'Heap buffer overflow in WebP in Google Chrome prior to 116.0.5845.187 allowed a remote attacker to perform an out-of-bounds memory write via a crafted HTML page.',
            'cvss_score': 8.8,
            'severity': Severity.HIGH,
            'affected_versions': '< 1.3.2',
            'fixed_version': '1.3.2',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2023, 9, 12)
        },
        {
            'cve_id': 'CVE-2022-22965',
            'software': 'Spring Framework',
            'vendor': 'VMware',
            'description': 'Spring Framework RCE via Data Binder (Spring4Shell) allows unauthenticated remote code execution on Tomcat servers running JDK 9+.',
            'cvss_score': 9.8,
            'severity': Severity.CRITICAL,
            'affected_versions': '5.3.0 to 5.3.17',
            'fixed_version': '5.3.18',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2022, 3, 31)
        },
        {
            'cve_id': 'CVE-2024-DEMO-0001',
            'software': 'DemoApp',
            'vendor': 'Demo Corp',
            'description': '[DEMO / FICTIONAL RECORD] Fictional SQL injection vulnerability in legacy authentication endpoint for testing and demonstration purposes.',
            'cvss_score': 5.3,
            'severity': Severity.MEDIUM,
            'affected_versions': '1.0.0',
            'fixed_version': None,
            'patch_available': False,
            'exploit_available': False,
            'published_date': date(2024, 1, 15)
        },
        {
            'cve_id': 'CVE-2024-DEMO-0002',
            'software': 'TestLogger',
            'vendor': 'Test Labs',
            'description': '[DEMO / FICTIONAL RECORD] Fictional information disclosure vulnerability exposing internal log filenames in debug header.',
            'cvss_score': 3.1,
            'severity': Severity.LOW,
            'affected_versions': '0.9.0',
            'fixed_version': '0.9.1',
            'patch_available': True,
            'exploit_available': False,
            'published_date': date(2024, 2, 20)
        }
    ]

    added = 0
    for rec in records:
        existing = Vulnerability.query.filter_by(cve_id=rec['cve_id']).first()
        if not existing:
            v = Vulnerability(**rec)
            db.session.add(v)
            added += 1

    db.session.commit()
    click.echo(f"Successfully seeded {added} vulnerability records.")

@click.command('init-db')
@click.option('--drop', is_flag=True, default=False, help='Drop existing tables first.')
def init_db_command(drop):
    """Initialize or rebuild the database schema."""
    if drop:
        click.confirm("Are you sure you want to drop all existing tables?", abort=True)
        db.drop_all()
        click.echo("Dropped all existing tables.")
    db.create_all()
    click.echo("Database schema initialized successfully.")

@click.command('seed-demo-data')
@click.option('--password', default='AdminSecret123!', help='Default password for seeded demo accounts.')
def seed_demo_data_command(password):
    """Seed comprehensive realistic demonstration data (Users, Depts, Assets, Software, CVEs, Scans)."""
    from epcras.models.asset import Asset, Department, Criticality
    from epcras.models.software import Software, InstalledSoftware
    from epcras.services.compliance_service import run_compliance_analysis
    
    db.create_all()
    click.echo("Seeding realistic enterprise demo dataset...")

    # 1. Seed Roles/Users
    users_data = [
        ('admin', 'admin@epcras.local', Role.ADMINISTRATOR),
        ('analyst', 'analyst@epcras.local', Role.SECURITY_ANALYST),
        ('support', 'support@epcras.local', Role.IT_SUPPORT),
        ('auditor', 'auditor@epcras.local', Role.AUDITOR)
    ]
    for uname, uemail, urole in users_data:
        u = User.query.filter_by(username=uname).first()
        if not u:
            u = User(username=uname, email=uemail, role=urole, is_active=True)
            u.set_password(password)
            db.session.add(u)
        else:
            u.set_password(password)
            u.is_active = True
    db.session.commit()
    click.echo("✓ Users seeded (admin, analyst, support, auditor)")

    # 2. Seed Departments
    dept_names = [
        ('Core Infrastructure', 'Mission-critical datacenter & networking operations'),
        ('Corporate Banking', 'High-security financial processing and ledger systems'),
        ('Payment Gateway Operations', 'PCI-DSS regulated card transaction gateway'),
        ('Customer Portal & Web Apps', 'Customer-facing public web applications'),
        ('Data & Analytics Platform', 'Enterprise data warehouse and streaming pipelines'),
        ('Corporate IT & Endpoints', 'Internal employee workstations and office infrastructure')
    ]
    depts = {}
    for name, desc in dept_names:
        d = Department.query.filter_by(name=name).first()
        if not d:
            d = Department(name=name, description=desc)
            db.session.add(d)
            db.session.flush()
        depts[name] = d
    db.session.commit()
    click.echo(f"✓ {len(depts)} Departments seeded")

    # 3. Seed Software Catalogue
    software_catalogue = [
        ('OpenSSL', 'OpenSSL Project', 'Cryptography'),
        ('Log4j', 'Apache Software Foundation', 'Logging Framework'),
        ('curl', 'Haxx', 'Networking Utility'),
        ('xz-utils', 'Tukaani', 'Compression Utility'),
        ('sudo', 'Sudo Team', 'System Administration'),
        ('libwebp', 'Google', 'Multimedia Library'),
        ('Spring Framework', 'VMware', 'Application Framework'),
        ('PostgreSQL', 'PostgreSQL Global Development Group', 'Database Engine'),
        ('Nginx', 'F5 NGINX', 'Reverse Proxy & Web Server'),
        ('Redis', 'Redis Ltd', 'In-Memory Data Store'),
        ('Node.js', 'OpenJS Foundation', 'JavaScript Runtime'),
        ('Docker Engine', 'Docker Inc', 'Container Runtime')
    ]
    softwares = {}
    for sw_name, vendor, cat in software_catalogue:
        sw = Software.query.filter_by(name=sw_name).first()
        if not sw:
            sw = Software(name=sw_name, vendor=vendor, category=cat)
            db.session.add(sw)
            db.session.flush()
        softwares[sw_name] = sw
    db.session.commit()
    click.echo(f"✓ {len(softwares)} Software catalogue entries seeded")

    # 4. Seed Assets
    assets_data = [
        ('PROD-DB-CLUSTER-01', '10.10.10.11', 'Ubuntu Linux', '22.04 LTS', 'Corporate Banking', 'Server', Criticality.CRITICAL, 'DBA Team'),
        ('PROD-PAYMENT-GW-01', '10.10.20.15', 'Red Hat Enterprise Linux', '9.2', 'Payment Gateway Operations', 'Server', Criticality.CRITICAL, 'SecOps'),
        ('PROD-WEB-FRONTEND-01', '10.10.30.22', 'Debian GNU/Linux', '12', 'Customer Portal & Web Apps', 'Server', Criticality.HIGH, 'WebOps'),
        ('PROD-KAFKA-STREAM-01', '10.10.40.35', 'Ubuntu Linux', '22.04 LTS', 'Data & Analytics Platform', 'Server', Criticality.HIGH, 'DataOps'),
        ('CORE-ROUTER-EDGE-01', '10.10.0.1', 'Cisco IOS-XE', '17.6', 'Core Infrastructure', 'Network Device', Criticality.CRITICAL, 'NetOps'),
        ('SEC-SIEM-COLLECTOR-01', '10.10.50.8', 'Rocky Linux', '9.3', 'Core Infrastructure', 'Server', Criticality.HIGH, 'SOC Team'),
        ('CORP-DEV-WS-101', '172.16.10.101', 'Windows 11 Enterprise', '23H2', 'Corporate IT & Endpoints', 'Workstation', Criticality.MEDIUM, 'Dev Team'),
        ('CORP-FIN-WS-204', '172.16.20.204', 'macOS Sonoma', '14.4', 'Corporate Banking', 'Workstation', Criticality.MEDIUM, 'Finance Ops'),
        ('CORP-HELPDESK-05', '172.16.30.55', 'Windows 11 Enterprise', '23H2', 'Corporate IT & Endpoints', 'Workstation', Criticality.LOW, 'Helpdesk'),
        ('STAGING-API-NODE-01', '10.20.10.50', 'Ubuntu Linux', '22.04 LTS', 'Customer Portal & Web Apps', 'Virtual Machine', Criticality.LOW, 'QA Team')
    ]
    assets = {}
    for hname, ip, os_name, os_ver, dept_name, atype, crit, owner in assets_data:
        a = Asset.query.filter_by(hostname=hname).first()
        if not a:
            a = Asset(
                hostname=hname,
                ip_address=ip,
                operating_system=os_name,
                os_version=os_ver,
                department_id=depts[dept_name].id,
                asset_type=atype,
                criticality=crit,
                owner=owner
            )
            db.session.add(a)
            db.session.flush()
        assets[hname] = a
    db.session.commit()
    click.echo(f"✓ {len(assets)} Assets seeded")

    # 5. Link Installed Software
    installations = [
        # PROD-DB-CLUSTER-01 (Critical): PostgreSQL 12.4 (vuln), OpenSSL 1.1.1f (vuln), sudo 1.8.31
        ('PROD-DB-CLUSTER-01', 'PostgreSQL', '12.4'),
        ('PROD-DB-CLUSTER-01', 'OpenSSL', '1.1.1f'),
        ('PROD-DB-CLUSTER-01', 'sudo', '1.8.31'),
        # PROD-PAYMENT-GW-01 (Critical): OpenSSL 1.1.1d (vuln), curl 7.68.0 (vuln), Nginx 1.18.0
        ('PROD-PAYMENT-GW-01', 'OpenSSL', '1.1.1d'),
        ('PROD-PAYMENT-GW-01', 'curl', '7.68.0'),
        ('PROD-PAYMENT-GW-01', 'Nginx', '1.18.0'),
        # PROD-WEB-FRONTEND-01 (High): Nginx 1.24.0 (patched), Node.js 18.16.0, libwebp 1.2.4 (vuln)
        ('PROD-WEB-FRONTEND-01', 'Nginx', '1.24.0'),
        ('PROD-WEB-FRONTEND-01', 'Node.js', '18.16.0'),
        ('PROD-WEB-FRONTEND-01', 'libwebp', '1.2.4'),
        # PROD-KAFKA-STREAM-01 (High): Log4j 2.14.1 (vuln), Spring Framework 5.3.15 (vuln)
        ('PROD-KAFKA-STREAM-01', 'Log4j', '2.14.1'),
        ('PROD-KAFKA-STREAM-01', 'Spring Framework', '5.3.15'),
        # SEC-SIEM-COLLECTOR-01 (High): xz-utils 5.6.0 (vuln), Redis 7.0.10
        ('SEC-SIEM-COLLECTOR-01', 'xz-utils', '5.6.0'),
        ('SEC-SIEM-COLLECTOR-01', 'Redis', '7.0.10'),
        # CORP-DEV-WS-101 (Medium): Docker Engine 24.0.5, curl 8.4.0 (patched), sudo 1.9.5 (patched)
        ('CORP-DEV-WS-101', 'Docker Engine', '24.0.5'),
        ('CORP-DEV-WS-101', 'curl', '8.4.0'),
        ('CORP-DEV-WS-101', 'sudo', '1.9.5'),
        # CORP-FIN-WS-204 (Medium): OpenSSL 1.1.1w (patched), curl 8.4.0 (patched), PostgreSQL 15.2 (patched)
        ('CORP-FIN-WS-204', 'OpenSSL', '1.1.1w'),
        ('CORP-FIN-WS-204', 'curl', '8.4.0'),
        ('CORP-FIN-WS-204', 'PostgreSQL', '15.2'),
        # CORP-HELPDESK-05 (Low): Node.js 20.10.0, Nginx 1.24.0
        ('CORP-HELPDESK-05', 'Node.js', '20.10.0'),
        ('CORP-HELPDESK-05', 'Nginx', '1.24.0'),
        # STAGING-API-NODE-01 (Low): Spring Framework 5.3.20 (patched), Redis 7.2.0 (patched)
        ('STAGING-API-NODE-01', 'Spring Framework', '5.3.20'),
        ('STAGING-API-NODE-01', 'Redis', '7.2.0')
    ]
    for hname, sw_name, ver in installations:
        a = assets[hname]
        sw = softwares[sw_name]
        inst = InstalledSoftware.query.filter_by(asset_id=a.id, software_id=sw.id).first()
        if not inst:
            inst = InstalledSoftware(asset_id=a.id, software_id=sw.id, version=ver)
            db.session.add(inst)
        else:
            inst.version = ver
    db.session.commit()
    click.echo(f"✓ {len(installations)} Software installations linked across assets")

    # 6. Seed Vulnerabilities
    cves = [
        {
            'cve_id': 'CVE-2021-44228',
            'software': 'Log4j',
            'vendor': 'Apache Software Foundation',
            'description': 'Log4Shell: Remote code execution in Log4j JNDI lookup functionality.',
            'cvss_score': 10.0,
            'severity': Severity.CRITICAL,
            'affected_versions': '2.0-beta9 <= 2.14.1',
            'fixed_version': '2.17.1',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2021, 12, 10)
        },
        {
            'cve_id': 'CVE-2024-3094',
            'software': 'xz-utils',
            'vendor': 'Tukaani',
            'description': 'Malicious backdoor in upstream XZ Utils builds affecting SSH daemon authentication.',
            'cvss_score': 10.0,
            'severity': Severity.CRITICAL,
            'affected_versions': '5.6.0, 5.6.1',
            'fixed_version': '5.6.2',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2024, 3, 29)
        },
        {
            'cve_id': 'CVE-2021-3711',
            'software': 'OpenSSL',
            'vendor': 'OpenSSL Project',
            'description': 'SM2 Decryption Buffer Overflow vulnerability in OpenSSL.',
            'cvss_score': 9.8,
            'severity': Severity.CRITICAL,
            'affected_versions': '< 1.1.1l',
            'fixed_version': '1.1.1l',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2021, 8, 24)
        },
        {
            'cve_id': 'CVE-2022-22965',
            'software': 'Spring Framework',
            'vendor': 'VMware',
            'description': 'Spring4Shell: Remote code execution via Data Binder on JDK 9+.',
            'cvss_score': 9.8,
            'severity': Severity.CRITICAL,
            'affected_versions': '5.3.0 to 5.3.17',
            'fixed_version': '5.3.18',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2022, 3, 31)
        },
        {
            'cve_id': 'CVE-2023-38545',
            'software': 'curl',
            'vendor': 'Haxx',
            'description': 'SOCKS5 heap buffer overflow in libcurl during SOCKS5 proxy handshake.',
            'cvss_score': 9.8,
            'severity': Severity.CRITICAL,
            'affected_versions': '< 8.4.0',
            'fixed_version': '8.4.0',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2023, 10, 11)
        },
        {
            'cve_id': 'CVE-2023-4863',
            'software': 'libwebp',
            'vendor': 'Google',
            'description': 'Heap buffer overflow in WebP lossless decompression in libwebp.',
            'cvss_score': 8.8,
            'severity': Severity.HIGH,
            'affected_versions': '< 1.3.2',
            'fixed_version': '1.3.2',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2023, 9, 12)
        },
        {
            'cve_id': 'CVE-2020-25695',
            'software': 'PostgreSQL',
            'vendor': 'PostgreSQL Global Development Group',
            'description': 'Multiple features escape function parameters allowing arbitrary SQL execution and privilege escalation.',
            'cvss_score': 8.8,
            'severity': Severity.HIGH,
            'affected_versions': '< 12.5',
            'fixed_version': '12.5',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2020, 11, 12)
        },
        {
            'cve_id': 'CVE-2021-3156',
            'software': 'sudo',
            'vendor': 'Sudo Team',
            'description': 'Baron Samedit: Heap-based buffer overflow in Sudo allows unprivileged user privilege escalation to root.',
            'cvss_score': 7.8,
            'severity': Severity.HIGH,
            'affected_versions': '< 1.9.5',
            'fixed_version': '1.9.5',
            'patch_available': True,
            'exploit_available': True,
            'published_date': date(2021, 1, 26)
        }
    ]
    for cve in cves:
        v = Vulnerability.query.filter_by(cve_id=cve['cve_id']).first()
        if not v:
            v = Vulnerability(**cve)
            db.session.add(v)
    db.session.commit()
    click.echo(f"✓ {len(cves)} CVE Vulnerability advisories seeded")

    # 7. Execute Organization-Wide Compliance Scan
    click.echo("Running compliance scan to correlate inventory with advisories...")
    scan_results = run_compliance_analysis()
    click.echo(
        f"✓ Compliance Analysis Complete: {scan_results['scanned_installations']} scanned, "
        f"{scan_results['non_compliant_findings']} non-compliant findings, "
        f"{scan_results['compliant_count']} compliant, {scan_results['unknown_count']} unknown"
    )

    log_audit_event(
        action_category='DEMO_SEED',
        username='CLI_SEED',
        target_entity='System',
        details='Realistic enterprise demo dataset successfully initialized via CLI',
        status='SUCCESS'
    )
    click.echo("\n=======================================================")
    click.echo("  EPCRAS Enterprise Demo Dataset Ready!")
    click.echo("=======================================================")
    click.echo(f"  Login URL:      http://127.0.0.1:5000/auth/login")
    click.echo(f"  Administrator:  admin   / {password}")
    click.echo(f"  Sec Analyst:    analyst / {password}")
    click.echo(f"  IT Support:     support / {password}")
    click.echo(f"  Auditor:        auditor / {password}")
    click.echo("=======================================================\n")

def register_cli_commands(app):
    app.cli.add_command(init_db_command)
    app.cli.add_command(seed_admin_command)
    app.cli.add_command(seed_vulnerabilities_command)
    app.cli.add_command(seed_demo_data_command)
