from epcras.services.report_service import ReportType

def login_as(client, username, password):
    return client.post('/auth/login', data={
        'username_or_email': username,
        'password': password
    }, follow_redirects=True)

def test_reports_index_route(client, analyst_user):
    # Unauthenticated
    resp = client.get('/reports/')
    assert resp.status_code in (302, 401)

    # Authenticated
    login_as(client, analyst_user.username, 'AnalystSecret123!')
    resp = client.get('/reports/')
    assert resp.status_code == 200
    assert b'Report Center' in resp.data

def test_report_export_csv(client, admin_user):
    login_as(client, admin_user.username, 'AdminSecret123!')

    for rtype in ReportType.all_types():
        resp = client.get(f'/reports/export/{rtype}/csv')
        assert resp.status_code == 200
        assert resp.mimetype == 'text/csv'
        assert 'attachment;' in resp.headers['Content-Disposition']
        assert rtype.lower() in resp.headers['Content-Disposition']

def test_report_export_pdf(client, admin_user):
    login_as(client, admin_user.username, 'AdminSecret123!')

    for rtype in ReportType.all_types():
        resp = client.get(f'/reports/export/{rtype}/pdf')
        assert resp.status_code == 200
        assert resp.mimetype == 'application/pdf'
        assert 'attachment;' in resp.headers['Content-Disposition']
        assert rtype.lower() in resp.headers['Content-Disposition']
        assert resp.data.startswith(b'%PDF')

def test_report_export_invalid_type_and_format(client, admin_user):
    login_as(client, admin_user.username, 'AdminSecret123!')

    # Invalid report type
    resp_invalid_type = client.get('/reports/export/NON_EXISTENT_REPORT/csv', follow_redirects=True)
    assert resp_invalid_type.status_code == 200
    assert b"Invalid report type requested" in resp_invalid_type.data

    # Invalid format
    resp_invalid_fmt = client.get('/reports/export/OVERALL_COMPLIANCE/xml', follow_redirects=True)
    assert resp_invalid_fmt.status_code == 200
    assert b"Invalid export format requested" in resp_invalid_fmt.data


