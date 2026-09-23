import pytest
from epcras.models.asset import Asset, Department, Criticality
from epcras.services.asset_service import (
    create_asset, update_asset, delete_asset, get_all_assets, create_department, get_all_departments,
    get_asset_by_id, get_asset_by_hostname
)
from epcras.services.software_service import get_or_create_software, add_installed_software
from epcras.models.software import InstalledSoftware
from epcras.models.compliance import ComplianceResult, ComplianceStatus

def test_department_creation(app):
    dept = create_department("Finance", "Finance Department IT Assets")
    assert dept.id is not None
    assert dept.name == "Finance"
    assert len(get_all_departments()) == 1

def test_asset_crud(app):
    dept = create_department("IT Security")

    # Create Asset
    asset_data = {
        'hostname': 'SEC-HOST-01',
        'ip_address': '192.168.1.100',
        'operating_system': 'Ubuntu Linux',
        'os_version': '22.04',
        'department_id': dept.id,
        'owner': 'Jane Doe',
        'asset_type': 'Server',
        'criticality': Criticality.HIGH
    }
    asset = create_asset(asset_data)
    assert asset.id is not None
    assert asset.hostname == 'SEC-HOST-01'
    assert asset.criticality == Criticality.HIGH
    assert asset.department_name == 'IT Security'

    # Duplicate Hostname Prevention
    with pytest.raises(ValueError, match="already exists"):
        create_asset(asset_data)

    # Update Asset
    update_data = {
        'hostname': 'SEC-HOST-01-RENAMED',
        'ip_address': '192.168.1.101',
        'operating_system': 'Ubuntu Linux',
        'criticality': Criticality.CRITICAL
    }
    updated = update_asset(asset.id, update_data)
    assert updated.hostname == 'SEC-HOST-01-RENAMED'
    assert updated.criticality == Criticality.CRITICAL

    # Delete Asset
    assert delete_asset(asset.id) is True
    assert get_all_assets() == []

def test_asset_filtering_and_search(app):
    dept1 = create_department("Finance")
    dept2 = create_department("Engineering")

    create_asset({
        'hostname': 'FIN-PC01', 'ip_address': '10.0.0.1',
        'operating_system': 'Windows 11', 'department_id': dept1.id,
        'criticality': Criticality.LOW, 'asset_type': 'Workstation'
    })
    create_asset({
        'hostname': 'ENG-SRV01', 'ip_address': '10.0.0.2',
        'operating_system': 'Red Hat Enterprise Linux', 'department_id': dept2.id,
        'criticality': Criticality.CRITICAL, 'asset_type': 'Server'
    })

    # Search query
    results_search = get_all_assets(search_query='Red Hat')
    assert len(results_search) == 1
    assert results_search[0].hostname == 'ENG-SRV01'

    # Filter by criticality
    results_crit = get_all_assets(criticality=Criticality.CRITICAL)
    assert len(results_crit) == 1
    assert results_crit[0].hostname == 'ENG-SRV01'

    # Filter by department
    results_dept = get_all_assets(department_id=dept1.id)
    assert len(results_dept) == 1
    assert results_dept[0].hostname == 'FIN-PC01'

    # Filter by asset_type
    results_type = get_all_assets(asset_type='Server')
    assert len(results_type) == 1
    assert results_type[0].hostname == 'ENG-SRV01'

def test_asset_lookup_by_hostname_and_id(app):
    asset = create_asset({'hostname': 'LOOKUP-HOST', 'ip_address': '10.0.0.99', 'operating_system': 'Linux'})

    assert get_asset_by_hostname('lookup-host').id == asset.id
    assert get_asset_by_hostname('LOOKUP-HOST').id == asset.id
    assert get_asset_by_hostname('') is None
    assert get_asset_by_hostname(None) is None

    assert get_asset_by_id(asset.id).hostname == 'LOOKUP-HOST'
    assert get_asset_by_id(999999) is None

def test_asset_update_edge_cases(app):
    a1 = create_asset({'hostname': 'HOST-ALPHA', 'ip_address': '10.1.1.1', 'operating_system': 'Linux'})
    a2 = create_asset({'hostname': 'HOST-BETA', 'ip_address': '10.1.1.2', 'operating_system': 'Windows'})

    # Nonexistent asset
    with pytest.raises(ValueError, match="not found"):
        update_asset(999999, {'hostname': 'GHOST'})

    # Rename collision
    with pytest.raises(ValueError, match="already exists"):
        update_asset(a2.id, {'hostname': 'HOST-ALPHA'})

    # Case-only change
    updated = update_asset(a1.id, {'hostname': 'host-alpha'})
    assert updated.hostname == 'host-alpha'

def test_delete_asset_cascade_software_and_compliance(app):
    asset = create_asset({'hostname': 'CASCADE-HOST', 'ip_address': '10.2.2.1', 'operating_system': 'Linux'})
    sw = get_or_create_software("TestApp", "TestVendor")
    inst = add_installed_software(asset.id, sw.id, "1.0.0")

    # Add compliance result
    from epcras.extensions import db
    comp = ComplianceResult(
        asset_id=asset.id,
        installed_software_id=inst.id,
        software_name="TestApp",
        installed_version="1.0.0",
        status=ComplianceStatus.NON_COMPLIANT
    )
    db.session.add(comp)
    db.session.commit()

    asset_id = asset.id
    inst_id = inst.id
    comp_id = comp.id

    assert delete_asset(asset_id) is True

    # Asset deleted
    assert get_asset_by_id(asset_id) is None
    # Cascaded delete on InstalledSoftware
    assert db.session.get(InstalledSoftware, inst_id) is None
    # Cascaded delete on ComplianceResult
    assert db.session.get(ComplianceResult, comp_id) is None

    # Deleting already deleted asset returns False
    assert delete_asset(asset_id) is False

def test_asset_and_department_repr(app):
    dept = create_department("SecOps", "Security Operations")
    asset = create_asset({'hostname': 'REPR-HOST', 'ip_address': '10.3.3.1', 'operating_system': 'Linux', 'department_id': dept.id})

    assert 'SecOps' in repr(dept)
    assert 'REPR-HOST' in repr(asset)
    assert asset.department_name == 'SecOps'

    asset_no_dept = create_asset({'hostname': 'NODEPT-HOST', 'ip_address': '10.3.3.2', 'operating_system': 'Linux'})
    assert asset_no_dept.department_name == 'Unassigned'

