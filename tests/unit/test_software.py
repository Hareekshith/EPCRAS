import io
from epcras.models.software import Software, InstalledSoftware
from epcras.services.asset_service import create_asset
from epcras.services.software_service import (
    get_or_create_software, add_installed_software, remove_installed_software, import_software_csv
)

def test_software_catalogue_and_linking(app):
    asset = create_asset({
        'hostname': 'PC-DEV-01',
        'ip_address': '192.168.1.10',
        'operating_system': 'Linux'
    })

    sw = get_or_create_software("Firefox", "Mozilla", "Web Browser")
    assert sw.id is not None
    assert sw.name == "Firefox"

    installed = add_installed_software(asset.id, sw.id, "128.0")
    assert installed.id is not None
    assert installed.version == "128.0"
    assert asset.installed_software.count() == 1

    # Remove Installed Software
    assert remove_installed_software(installed.id) is True
    assert asset.installed_software.count() == 0

def test_csv_import_valid(app):
    csv_data = (
        "hostname,software,vendor,version\n"
        "PC001,Firefox,Mozilla,128.0\n"
        "PC001,Python,Python Software Foundation,3.10.0\n"
    )
    file_stream = io.BytesIO(csv_data.encode('utf-8'))
    result = import_software_csv(file_stream)

    assert result['success_count'] == 2
    assert len(result['errors']) == 0

    sw = Software.query.filter_by(name="Firefox").first()
    assert sw is not None
    assert sw.vendor == "Mozilla"

def test_csv_import_missing_columns(app):
    csv_data = "hostname,version\nPC001,1.0\n"
    file_stream = io.BytesIO(csv_data.encode('utf-8'))
    result = import_software_csv(file_stream)

    assert result['success_count'] == 0
    assert len(result['errors']) == 1
    assert "missing required columns" in result['errors'][0]

def test_csv_import_row_validation_errors(app):
    csv_data = (
        "hostname,software,vendor,version\n"
        ",Firefox,Mozilla,128.0\n"
        "PC002,,Mozilla,128.0\n"
        "PC003,Python,Python Software Foundation,\n"
    )
    file_stream = io.BytesIO(csv_data.encode('utf-8'))
    result = import_software_csv(file_stream)

    assert result['success_count'] == 0
    assert len(result['errors']) == 3
    assert "Row 2: hostname is missing" in result['errors'][0]
    assert "Row 3: software name is missing" in result['errors'][1]
    assert "Row 4: version is missing" in result['errors'][2]
