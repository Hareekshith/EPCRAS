from epcras.services.notification_service import create_notification, get_unread_count

def login_as(client, username, password):
    return client.post('/auth/login', data={
        'username_or_email': username,
        'password': password
    }, follow_redirects=True)

def test_search_route(client, analyst_user):
    login_as(client, analyst_user.username, 'AnalystSecret123!')

    resp = client.get('/search/?hostname=TEST')
    assert resp.status_code == 200
    assert b'Centralized System Search' in resp.data

def test_notifications_routes_and_actions(client, admin_user):
    login_as(client, admin_user.username, 'AdminSecret123!')

    n = create_notification("ROUTE_TEST", "Test Notification", "Route test message", severity="HIGH")
    assert get_unread_count() >= 1

    # GET notifications index
    resp = client.get('/notifications/')
    assert resp.status_code == 200
    assert b'Test Notification' in resp.data

    # POST read single
    resp = client.post(f'/notifications/{n.id}/read', follow_redirects=True)
    assert resp.status_code == 200

    # POST read all
    resp = client.post('/notifications/read-all', follow_redirects=True)
    assert resp.status_code == 200
    assert get_unread_count() == 0
