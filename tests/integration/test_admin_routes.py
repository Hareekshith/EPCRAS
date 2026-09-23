from epcras.extensions import db
from epcras.models.user import User, Role

def login_as(client, username, password):
    return client.post('/auth/login', data={
        'username_or_email': username,
        'password': password
    }, follow_redirects=True)

def test_admin_authorization_enforcement(client, admin_user, analyst_user, support_user):
    # 1. Unauthenticated -> Redirects to login
    for path in ['/admin/', '/admin/users', '/admin/users/new', '/admin/audit-logs']:
        resp = client.get(path)
        assert resp.status_code in (302, 401)

    # 2. Security Analyst -> 403 Forbidden on all admin endpoints
    login_as(client, analyst_user.username, 'AnalystSecret123!')
    for path in ['/admin/', '/admin/users', '/admin/users/new', '/admin/audit-logs']:
        resp = client.get(path)
        assert resp.status_code == 403
    client.get('/auth/logout')

    # 3. IT Support -> 403 Forbidden
    login_as(client, support_user.username, 'SupportSecret123!')
    resp = client.get('/admin/')
    assert resp.status_code == 403
    client.get('/auth/logout')

    # 4. Administrator -> 200 OK
    login_as(client, admin_user.username, 'AdminSecret123!')
    for path in ['/admin/', '/admin/users', '/admin/users/new', '/admin/audit-logs']:
        resp = client.get(path)
        assert resp.status_code == 200

def test_admin_create_and_toggle_user_flow(client, admin_user):
    login_as(client, admin_user.username, 'AdminSecret123!')

    # Create new analyst user via admin route
    resp = client.post('/admin/users/new', data={
        'username': 'created_analyst',
        'email': 'created_analyst@epcras.org',
        'password': 'CreatedSecret123!',
        'role': Role.SECURITY_ANALYST,
        'is_active': 'y'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b'created_analyst' in resp.data

    created = User.query.filter_by(username='created_analyst').first()
    assert created is not None
    assert created.role == Role.SECURITY_ANALYST

    # Toggle active status to disabled
    resp_toggle = client.post(f'/admin/users/{created.id}/toggle-status', follow_redirects=True)
    assert resp_toggle.status_code == 200
    assert created.is_active is False

    # Logout admin
    client.get('/auth/logout')

    # Attempt to log in as disabled user -> fails
    resp_login = client.post('/auth/login', data={
        'username_or_email': 'created_analyst',
        'password': 'CreatedSecret123!'
    }, follow_redirects=True)
    assert b'disabled' in resp_login.data or b'Invalid username/email or password' in resp_login.data

def test_admin_edit_user_route(client, admin_user, support_user):
    login_as(client, admin_user.username, 'AdminSecret123!')

    resp = client.post(f'/admin/users/{support_user.id}/edit', data={
        'username': support_user.username,
        'email': 'new_support@epcras.org',
        'role': Role.SECURITY_ANALYST,
        'is_active': 'y'
    }, follow_redirects=True)

    assert resp.status_code == 200
    updated_user = db.session.get(User, support_user.id)
    assert updated_user.email == 'new_support@epcras.org'
    assert updated_user.role == Role.SECURITY_ANALYST

def test_admin_audit_log_viewer_filtering(client, admin_user):
    login_as(client, admin_user.username, 'AdminSecret123!')

    resp = client.get('/admin/audit-logs?action_category=LOGIN')
    assert resp.status_code == 200
    assert b'Audit Records' in resp.data

def test_admin_user_form_validation_and_nonexistent(client, admin_user):
    login_as(client, admin_user.username, 'AdminSecret123!')

    # Form validation error on create: short password & invalid email
    resp_create_err = client.post('/admin/users/new', data={
        'username': 'invalid_u',
        'email': 'not-an-email',
        'password': 'short',
        'role': Role.AUDITOR
    }, follow_redirects=True)
    assert resp_create_err.status_code == 200
    assert b'Password must be at least 8 characters' in resp_create_err.data or b'Invalid email' in resp_create_err.data

    # Edit non-existent user
    resp_edit_none = client.get('/admin/users/999999/edit', follow_redirects=True)
    assert resp_edit_none.status_code == 200
    assert b'User account not found' in resp_edit_none.data

    # Toggle non-existent user
    resp_toggle_none = client.post('/admin/users/999999/toggle-status', follow_redirects=True)
    assert resp_toggle_none.status_code == 200
    assert b'does not exist' in resp_toggle_none.data

