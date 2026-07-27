from datetime import date
import click
from flask.cli import AppGroup
from epcras.extensions import db
from epcras.models.user import User, Role
from epcras.models.vulnerability import Vulnerability, Severity
from epcras.services.audit_service import log_audit_event

admin_cli = AppGroup('admin', help='Administrative CLI commands.')

@click.command('seed-admin')
@click.option('--username', default='admin', help='Admin username (default: admin)')
@click.option('--email', default='admin@epcras.local', help='Admin email (default: admin@epcras.local)')
@click.option('--password', default='hari3118', help='Admin password (default: hari3118)')
def seed_admin_command(username, email, password):
    """Seed or update the administrator user."""
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

def register_cli_commands(app):
    app.cli.add_command(seed_admin_command)
    app.cli.add_command(seed_vulnerabilities_command)
