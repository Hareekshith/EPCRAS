from flask import url_for

def test_login_page_renders(client):
    response = client.get('/auth/login')
    assert response.status_code == 200
    assert b"EPCRAS System Sign In" in response.data
    assert b"Public registration is disabled" in response.data

def test_valid_login_flow(client, admin_user):
    response = client.post('/auth/login', data={
        'username_or_email': 'admin_test',
        'password': 'AdminSecret123!'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Welcome, admin_test" in response.data
    assert b"Dashboard" in response.data

def test_invalid_login_flow(client, admin_user):
    response = client.post('/auth/login', data={
        'username_or_email': 'admin_test',
        'password': 'WrongPassword'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Invalid username/email or password" in response.data

def test_logout_flow(client, admin_user):
    # Log in first
    client.post('/auth/login', data={
        'username_or_email': 'admin_test',
        'password': 'AdminSecret123!'
    })

    # Log out
    response = client.get('/auth/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b"You have been logged out" in response.data
    assert b"EPCRAS System Sign In" in response.data

def test_unauthorized_access_redirect(client):
    # Access dashboard without logging in -> redirects to login
    response = client.get('/dashboard', follow_redirects=True)
    assert response.status_code == 200
    assert b"EPCRAS System Sign In" in response.data
    assert b"Please log in to access this page" in response.data

def test_role_restrictions_admin_only(client, admin_user, analyst_user, support_user):
    # Support user attempts admin endpoint -> 403 Forbidden
    client.post('/auth/login', data={'username_or_email': 'support_test', 'password': 'SupportSecret123!'})
    resp_support = client.get('/admin-only')
    assert resp_support.status_code == 403
    assert b"Access Forbidden" in resp_support.data
    client.get('/auth/logout')

    # Analyst user attempts admin endpoint -> 403 Forbidden
    client.post('/auth/login', data={'username_or_email': 'analyst_test', 'password': 'AnalystSecret123!'})
    resp_analyst = client.get('/admin-only')
    assert resp_analyst.status_code == 403
    client.get('/auth/logout')

    # Admin user attempts admin endpoint -> 200 OK
    client.post('/auth/login', data={'username_or_email': 'admin_test', 'password': 'AdminSecret123!'})
    resp_admin = client.get('/admin-only')
    assert resp_admin.status_code == 200
    assert b"Admin Only Access Granted" in resp_admin.data

def test_role_restrictions_analyst_only(client, analyst_user, support_user):
    # Support user attempts analyst endpoint -> 403 Forbidden
    client.post('/auth/login', data={'username_or_email': 'support_test', 'password': 'SupportSecret123!'})
    resp_support = client.get('/analyst-only')
    assert resp_support.status_code == 403
    client.get('/auth/logout')

    # Analyst user attempts analyst endpoint -> 200 OK
    client.post('/auth/login', data={'username_or_email': 'analyst_test', 'password': 'AnalystSecret123!'})
    resp_analyst = client.get('/analyst-only')
    assert resp_analyst.status_code == 200
    assert b"Analyst Access Granted" in resp_analyst.data
