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

def test_user_roles(app, admin_user, analyst_user, support_user, auditor_user):
    assert admin_user.has_role(Role.ADMINISTRATOR) is True
    assert admin_user.has_role(Role.SECURITY_ANALYST) is False
    assert admin_user.is_admin is True

    assert analyst_user.has_role(Role.SECURITY_ANALYST) is True
    assert analyst_user.has_role(Role.ADMINISTRATOR) is False

    assert support_user.has_role(Role.IT_SUPPORT) is True
    assert support_user.is_admin is False

    assert auditor_user.has_role(Role.AUDITOR) is True
    assert auditor_user.has_role(Role.ADMINISTRATOR, Role.AUDITOR) is True
    assert auditor_user.is_admin is False

    # Role choices and list
    assert len(Role.all_roles()) == 4
    assert len(Role.choices()) == 4

def test_authenticate_user_case_insensitive(app, admin_user):
    # Username uppercase
    user, err = authenticate_user('ADMIN_TEST', 'AdminSecret123!')
    assert user is not None
    assert err is None
    assert user.id == admin_user.id

    # Email mixed case
    user, err = authenticate_user('AdMiN@TeSt.CoM', 'AdminSecret123!')
    assert user is not None
    assert err is None

def test_authenticate_user_missing_or_empty_inputs(app):
    user, err = authenticate_user('', 'pass')
    assert user is None
    assert "Username/email and password are required" in err

    user, err = authenticate_user('user', '')
    assert user is None
    assert "Username/email and password are required" in err

    user, err = authenticate_user(None, None)
    assert user is None
    assert "Username/email and password are required" in err

def test_authenticate_user_records_ip_and_user_agent(app, admin_user):
    ip = '203.0.113.42'
    ua = 'EPCRAS-Audit-Client/1.0'

    # Success
    user, _ = authenticate_user('admin_test', 'AdminSecret123!', ip_address=ip, user_agent=ua)
    history = LoginHistory.query.filter_by(username='admin_test', status='SUCCESS').order_by(LoginHistory.id.desc()).first()
    assert history.ip_address == ip
    assert history.user_agent == ua

    # Failure
    _, _ = authenticate_user('admin_test', 'BadPass', ip_address=ip, user_agent=ua)
    history_fail = LoginHistory.query.filter_by(username='admin_test', status='FAILED').order_by(LoginHistory.id.desc()).first()
    assert history_fail.ip_address == ip
    assert history_fail.user_agent == ua

def test_user_and_login_history_repr(app, admin_user):
    user_repr = repr(admin_user)
    assert 'admin_test' in user_repr
    assert 'ADMINISTRATOR' in user_repr

    history = LoginHistory(username='test_user', status='SUCCESS')
    hist_repr = repr(history)
    assert 'test_user' in hist_repr
    assert 'SUCCESS' in hist_repr

def test_user_loader(app, admin_user):
    from epcras.extensions import login_manager
    user_loader = login_manager._user_callback
    loaded = user_loader(str(admin_user.id))
    assert loaded is not None
    assert loaded.id == admin_user.id

    assert user_loader('999999') is None

def test_seed_admin_cli(app, runner):
    result = runner.invoke(args=['seed-admin', '--username', 'cliadmin', '--password', 'CliAdminPass123!'])
    assert result.exit_code == 0
    assert "Successfully created administrator user 'cliadmin'" in result.output

    user = User.query.filter_by(username='cliadmin').first()
    assert user is not None
    assert user.role == Role.ADMINISTRATOR
    assert user.check_password('CliAdminPass123!') is True

