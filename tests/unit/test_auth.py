from epcras.models.user import User, Role, LoginHistory
from epcras.models.audit import AuditLog
from epcras.services.auth_service import authenticate_user
from epcras.extensions import db

def test_password_hashing(app):
    user = User(username='hashtest', email='hash@test.com', role=Role.IT_SUPPORT)
    user.set_password('SecretPass123!')
    assert user.password_hash != 'SecretPass123!'
    assert user.check_password('SecretPass123!') is True
    assert user.check_password('WrongPass') is False

def test_authenticate_user_success(app, admin_user):
    user, error = authenticate_user('admin_test', 'AdminSecret123!')
    assert user is not None
    assert error is None
    assert user.id == admin_user.id

    # Verify LoginHistory record
    history = LoginHistory.query.filter_by(username='admin_test').first()
    assert history is not None
    assert history.status == 'SUCCESS'

    # Verify AuditLog record
    audit = AuditLog.query.filter_by(username='admin_test', action_category='AUTH').first()
    assert audit is not None
    assert audit.status == 'SUCCESS'

def test_authenticate_user_by_email(app, admin_user):
    user, error = authenticate_user('admin@test.com', 'AdminSecret123!')
    assert user is not None
    assert error is None
    assert user.username == 'admin_test'

def test_authenticate_user_invalid_password(app, admin_user):
    user, error = authenticate_user('admin_test', 'WrongPassword123!')
    assert user is None
    assert "Invalid username/email or password" in error

    history = LoginHistory.query.filter_by(username='admin_test').first()
    assert history is not None
    assert history.status == 'FAILED'

def test_authenticate_user_nonexistent(app):
    user, error = authenticate_user('nonexistent_user', 'AnyPassword')
    assert user is None
    assert "Invalid username/email or password" in error

def test_authenticate_user_inactive(app, admin_user):
    admin_user.is_active = False
    db.session.commit()

    user, error = authenticate_user('admin_test', 'AdminSecret123!')
    assert user is None
    assert "Account is inactive" in error

def test_user_roles(app, admin_user, analyst_user, support_user):
    assert admin_user.has_role(Role.ADMINISTRATOR) is True
    assert admin_user.has_role(Role.SECURITY_ANALYST) is False
    assert admin_user.is_admin is True

    assert analyst_user.has_role(Role.SECURITY_ANALYST) is True
    assert analyst_user.has_role(Role.ADMINISTRATOR) is False

    assert support_user.has_role(Role.IT_SUPPORT) is True

def test_seed_admin_cli(app, runner):
    result = runner.invoke(args=['seed-admin', '--username', 'cliadmin', '--password', 'CliAdminPass123!'])
    assert result.exit_code == 0
    assert "Successfully created administrator user 'cliadmin'" in result.output

    user = User.query.filter_by(username='cliadmin').first()
    assert user is not None
    assert user.role == Role.ADMINISTRATOR
    assert user.check_password('CliAdminPass123!') is True
