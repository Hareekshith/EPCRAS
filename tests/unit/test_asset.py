import pytest
from epcras.models.asset import Asset, Department, Criticality
from epcras.services.asset_service import (
    create_asset, update_asset, delete_asset, get_all_assets, create_department, get_all_departments
)

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
