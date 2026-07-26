import io
from epcras.models.asset import Asset
from epcras.services.asset_service import create_asset

def test_asset_routes_admin_full_access(client, admin_user):
    # Log in as admin
    client.post('/auth/login', data={'username_or_email': 'admin_test', 'password': 'AdminSecret123!'})

    # Access index page
    res_index = client.get('/assets/')
    assert res_index.status_code == 200

    # Create new asset
    res_create = client.post('/assets/new', data={
        'hostname': 'ADMIN-PC01',
        'ip_address': '192.168.1.5',
        'operating_system': 'Windows 11',
        'asset_type': 'Workstation',
        'criticality': 'MEDIUM'
    }, follow_redirects=True)
    assert res_create.status_code == 200
    assert b"ADMIN-PC01" in res_create.data

    # Edit asset
    asset = Asset.query.filter_by(hostname='ADMIN-PC01').first()
    assert asset is not None
    res_edit = client.post(f'/assets/{asset.id}/edit', data={
        'hostname': 'ADMIN-PC01-EDITED',
        'ip_address': '192.168.1.6',
        'operating_system': 'Windows 11',
        'asset_type': 'Workstation',
        'criticality': 'HIGH'
    }, follow_redirects=True)
    assert res_edit.status_code == 200
    assert b"ADMIN-PC01-EDITED" in res_edit.data

    # Delete asset
    res_delete = client.post(f'/assets/{asset.id}/delete', follow_redirects=True)
    assert res_delete.status_code == 200
    assert Asset.query.filter_by(hostname='ADMIN-PC01-EDITED').first() is None

def test_asset_routes_it_support_access(client, support_user):
    client.post('/auth/login', data={'username_or_email': 'support_test', 'password': 'SupportSecret123!'})

    # IT support creates asset
    res_create = client.post('/assets/new', data={
        'hostname': 'SUPP-PC01',
        'ip_address': '192.168.1.20',
        'operating_system': 'Linux',
        'asset_type': 'Workstation',
        'criticality': 'LOW'
    }, follow_redirects=True)
    assert res_create.status_code == 200
    assert b"SUPP-PC01" in res_create.data

def test_asset_routes_security_analyst_read_only(client, analyst_user, admin_user):
    # Create asset as admin
    asset = create_asset({'hostname': 'ANALYST-TEST-PC', 'ip_address': '10.0.0.5', 'operating_system': 'Linux'})

    # Log in as Security Analyst
    client.post('/auth/login', data={'username_or_email': 'analyst_test', 'password': 'AnalystSecret123!'})

    # Read access: Index and Detail -> 200 OK
    res_index = client.get('/assets/')
    assert res_index.status_code == 200
    assert b"ANALYST-TEST-PC" in res_index.data

    res_detail = client.get(f'/assets/{asset.id}')
    assert res_detail.status_code == 200
    assert b"ANALYST-TEST-PC" in res_detail.data

    # Write operations -> 403 Forbidden
    res_create_attempt = client.get('/assets/new')
    assert res_create_attempt.status_code == 403

    res_edit_attempt = client.get(f'/assets/{asset.id}/edit')
    assert res_edit_attempt.status_code == 403

    res_delete_attempt = client.post(f'/assets/{asset.id}/delete')
    assert res_delete_attempt.status_code == 403

    res_import_attempt = client.get('/software/import')
    assert res_import_attempt.status_code == 403
