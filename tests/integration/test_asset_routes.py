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

def test_asset_software_link_and_delete_routes(client, admin_user):
    from epcras.services.software_service import get_or_create_software
    from epcras.models.software import InstalledSoftware

    client.post('/auth/login', data={'username_or_email': 'admin_test', 'password': 'AdminSecret123!'})

    asset = create_asset({'hostname': 'SW-LINK-PC', 'ip_address': '10.0.0.8', 'operating_system': 'Linux'})
    sw = get_or_create_software("TestApp", "TestVendor")

    # Link software
    resp_link = client.post(f'/assets/{asset.id}/software/add', data={
        'software_id': sw.id,
        'version': '3.2.1'
    }, follow_redirects=True)
    assert resp_link.status_code == 200
    assert b"TestApp" in resp_link.data
    assert b"3.2.1" in resp_link.data

    inst = InstalledSoftware.query.filter_by(asset_id=asset.id, software_id=sw.id).first()
    assert inst is not None

    # Delete software link
    resp_del_sw = client.post(f'/assets/{asset.id}/software/{inst.id}/delete', follow_redirects=True)
    assert resp_del_sw.status_code == 200
    assert b"Software association removed from asset" in resp_del_sw.data

def test_asset_routes_nonexistent_ids(client, admin_user):
    client.post('/auth/login', data={'username_or_email': 'admin_test', 'password': 'AdminSecret123!'})

    # Nonexistent detail
    resp_detail = client.get('/assets/999999', follow_redirects=True)
    assert resp_detail.status_code == 200
    assert b"Asset not found" in resp_detail.data

    # Nonexistent edit
    resp_edit = client.get('/assets/999999/edit', follow_redirects=True)
    assert resp_edit.status_code == 200
    assert b"Asset not found" in resp_edit.data

def test_asset_department_creation_route(client, admin_user):
    client.post('/auth/login', data={'username_or_email': 'admin_test', 'password': 'AdminSecret123!'})

    resp = client.post('/assets/departments', data={
        'name': 'Human Resources',
        'description': 'HR Department'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Human Resources" in resp.data


def test_asset_software_update_route(client, admin_user):
    from epcras.services.software_service import get_or_create_software, add_installed_software
    from epcras.models.software import InstalledSoftware

    client.post('/auth/login', data={'username_or_email': 'admin_test', 'password': 'AdminSecret123!'})

    asset = create_asset({'hostname': 'SW-UPDATE-PC', 'ip_address': '10.0.0.12', 'operating_system': 'Linux'})
    sw = get_or_create_software("PostgreSQL", "PostgreSQL Global Dev")
    inst = add_installed_software(asset.id, sw.id, "15.1")

    # Update version via route
    resp = client.post(f'/assets/{asset.id}/software/{inst.id}/update', data={
        'version': '15.4'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"to version 15.4" in resp.data

    inst_refreshed = db_get_inst(inst.id)
    assert inst_refreshed.version == "15.4"


def test_fleet_wide_upgrade_route(client, admin_user):
    from epcras.services.software_service import get_or_create_software, add_installed_software
    from epcras.models.software import InstalledSoftware

    client.post('/auth/login', data={'username_or_email': 'admin_test', 'password': 'AdminSecret123!'})

    a1 = create_asset({'hostname': 'UPGRADE-PC-01', 'ip_address': '10.0.0.14', 'operating_system': 'Linux'})
    a2 = create_asset({'hostname': 'UPGRADE-PC-02', 'ip_address': '10.0.0.15', 'operating_system': 'Linux'})
    sw = get_or_create_software("Python", "Python Software Foundation")
    inst1 = add_installed_software(a1.id, sw.id, "3.10.0")
    inst2 = add_installed_software(a2.id, sw.id, "3.10.0")

    resp = client.post('/software/bulk-upgrade', data={
        'software_id': str(sw.id),
        'target_version': '3.12.0'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Fleet upgrade complete" in resp.data

    assert db_get_inst(inst1.id).version == "3.12.0"
    assert db_get_inst(inst2.id).version == "3.12.0"


def db_get_inst(inst_id):
    from epcras.extensions import db
    from epcras.models.software import InstalledSoftware
    return db.session.get(InstalledSoftware, inst_id)


