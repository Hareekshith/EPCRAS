import click
from flask.cli import AppGroup
from epcras.extensions import db
from epcras.models.user import User, Role
from epcras.services.audit_service import log_audit_event

admin_cli = AppGroup('admin', help='Administrative CLI commands.')

@click.command('seed-admin')
@click.option('--username', default='admin', help='Admin username (default: admin)')
@click.option('--email', default='admin@epcras.local', help='Admin email (default: admin@epcras.local)')
@click.option('--password', default='AdminPassword123!', help='Admin password (default: AdminPassword123!)')
def seed_admin_command(username, email, password):
    """Seed the initial administrator user."""
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        click.echo(f"User '{existing_user.username}' already exists (Role: {existing_user.role}).")
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

def register_cli_commands(app):
    app.cli.add_command(seed_admin_command)
