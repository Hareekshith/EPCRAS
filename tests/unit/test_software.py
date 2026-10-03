import io
import codecs
import pytest
from epcras.models.software import Software, InstalledSoftware
from epcras.models.asset import Asset
from epcras.services.asset_service import create_asset
from epcras.services.software_service import (
    get_all_software, get_software_by_id, get_or_create_software, add_installed_software, remove_installed_software, import_software_csv
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

def test_software_catalogue_lookups_and_all(app):
    sw1 = get_or_create_software("Nginx", "F5", "Web Server")
    sw2 = get_or_create_software("Apache HTTP", "Apache", "Web Server")

    all_sw = get_all_software()
    assert len(all_sw) >= 2
    assert all_sw[0].name <= all_sw[1].name  # Alphabetical ordering

    assert get_software_by_id(sw1.id).name == "Nginx"
    assert get_software_by_id(999999) is None

def test_add_installed_software_validation_errors(app):
    asset = create_asset({'hostname': 'PC-VAL-01', 'ip_address': '10.0.0.1', 'operating_system': 'Linux'})
    sw = get_or_create_software("Vim", "Bram Moolenaar")

    # Nonexistent asset ID
    with pytest.raises(ValueError, match="Asset ID 999999 does not exist"):
        add_installed_software(999999, sw.id, "9.0")

    # Nonexistent software ID
    with pytest.raises(ValueError, match="Software ID 999999 does not exist"):
        add_installed_software(asset.id, 999999, "9.0")

    # Idempotent adding same software version
    inst1 = add_installed_software(asset.id, sw.id, "9.0")
    inst2 = add_installed_software(asset.id, sw.id, "9.0")
    assert inst1.id == inst2.id

    # Nonexistent installed software removal
    assert remove_installed_software(999999) is False

def test_csv_import_utf8_bom_and_case_insensitive_headers(app):
    csv_text = (
        "HOSTNAME,SOFTWARE,VENDOR,VERSION\n"
        "BOM-HOST,PostgreSQL,PostgreSQL Global Development Group,16.2\n"
    )
    bom_content = codecs.BOM_UTF8 + csv_text.encode('utf-8')
    result = import_software_csv(io.BytesIO(bom_content))

    assert result['success_count'] == 1
    assert len(result['errors']) == 0

    # Auto-created asset
    asset = Asset.query.filter_by(hostname='BOM-HOST').first()
    assert asset is not None
    assert asset.ip_address == "127.0.0.1"

def test_csv_import_empty_file_or_decode_error(app):
    # Completely empty file
    res_empty = import_software_csv(io.BytesIO(b""))
    assert res_empty['success_count'] == 0
    assert "empty or missing headers" in res_empty['errors'][0]

    # Corrupted binary that fails utf-8-sig decode
    corrupt_bytes = b"\xff\xfe\x00\x00\xaa\xbb\xcc\xdd"
    res_corrupt = import_software_csv(io.BytesIO(corrupt_bytes))
    assert res_corrupt['success_count'] == 0
    assert "Failed to read CSV file" in res_corrupt['errors'][0]

def test_software_and_installed_software_repr(app):
    asset = create_asset({'hostname': 'REPR-PC', 'ip_address': '10.0.0.2', 'operating_system': 'Linux'})
    sw = get_or_create_software("Git", "Software Freedom Conservancy")
    inst = add_installed_software(asset.id, sw.id, "2.44.0")

    assert "Git" in repr(sw)
    assert "2.44.0" in repr(inst)


def test_clean_fixed_version():
    from epcras.services.software_service import clean_fixed_version
    assert clean_fixed_version(">= 2.17.1") == "2.17.1"
    assert clean_fixed_version("2.4.51") == "2.4.51"
    assert clean_fixed_version("v1.2.3") == "1.2.3"
    assert clean_fixed_version(">= 3.0.0, < 4.0.0") == "3.0.0"
    assert clean_fixed_version("") == ""
    assert clean_fixed_version(None) == ""


def test_update_installed_software_version_and_compliance(app):
    from epcras.services.software_service import update_installed_software_version
    from epcras.services.vulnerability_service import create_vulnerability
    from epcras.services.compliance_service import run_compliance_analysis
    from epcras.models.compliance import ComplianceResult, ComplianceStatus

    asset = create_asset({'hostname': 'PATCH-TEST-01', 'ip_address': '10.0.1.1', 'operating_system': 'Linux'})
    sw = get_or_create_software("OpenSSL", "OpenSSL Project")
    inst = add_installed_software(asset.id, sw.id, "1.1.1")

    create_vulnerability({
        'cve_id': 'CVE-2021-3711',
        'software': 'OpenSSL',
        'vendor': 'OpenSSL Project',
        'cvss_score': 9.8,
        'severity': 'CRITICAL',
        'affected_versions': '1.1.1',
        'fixed_version': '1.1.1l'
    })

    # Initial scan -> Non-compliant
    run_compliance_analysis(asset_id=asset.id)
    findings = ComplianceResult.query.filter_by(asset_id=asset.id, status=ComplianceStatus.NON_COMPLIANT).all()
    assert len(findings) == 1

    # Validation errors
    with pytest.raises(ValueError, match="New software version cannot be empty"):
        update_installed_software_version(inst.id, "")

    with pytest.raises(ValueError, match="Installed software record ID 999999 not found"):
        update_installed_software_version(999999, "1.1.1l")

    # Update version to 1.1.1l -> Compliant, finding removed
    res = update_installed_software_version(inst.id, "1.1.1l", trigger_compliance=True)
    assert res['success'] is True
    assert res['new_version'] == "1.1.1l"
    assert res['already_updated'] is False

    # Already updated idempotent call
    res_idem = update_installed_software_version(inst.id, "1.1.1l", trigger_compliance=True)
    assert res_idem['already_updated'] is True

    findings_after = ComplianceResult.query.filter_by(asset_id=asset.id, status=ComplianceStatus.NON_COMPLIANT).all()
    assert len(findings_after) == 0


def test_bulk_patch_findings(app):
    from epcras.services.software_service import bulk_patch_findings
    from epcras.services.vulnerability_service import create_vulnerability
    from epcras.services.compliance_service import run_compliance_analysis
    from epcras.models.compliance import ComplianceResult, ComplianceStatus

    a1 = create_asset({'hostname': 'BULK-01', 'ip_address': '10.0.2.1', 'operating_system': 'Linux'})
    a2 = create_asset({'hostname': 'BULK-02', 'ip_address': '10.0.2.2', 'operating_system': 'Linux'})
    sw = get_or_create_software("Nginx", "F5")

    inst1 = add_installed_software(a1.id, sw.id, "1.20.0")
    inst2 = add_installed_software(a2.id, sw.id, "1.20.0")

    create_vulnerability({
        'cve_id': 'CVE-2021-23017',
        'software': 'Nginx',
        'vendor': 'F5',
        'cvss_score': 9.5,
        'severity': 'CRITICAL',
        'affected_versions': '1.20.0',
        'fixed_version': '1.20.1'
    })

    run_compliance_analysis()
    non_comp = ComplianceResult.query.filter_by(status=ComplianceStatus.NON_COMPLIANT).all()
    assert len(non_comp) >= 2

    # Bulk patch all fixable
    res = bulk_patch_findings(patch_all_fixable=True)
    assert res['updated_count'] >= 2

    # Verify both assets are now running 1.20.1 and compliant
    inst1_refreshed = db_get_inst(inst1.id)
    inst2_refreshed = db_get_inst(inst2.id)
    assert inst1_refreshed.version == "1.20.1"
    assert inst2_refreshed.version == "1.20.1"

    # Empty finding IDs handling
    empty_res = bulk_patch_findings(finding_ids=[])
    assert empty_res['updated_count'] == 0


def test_fleet_wide_software_upgrade(app):
    from epcras.services.software_service import fleet_wide_software_upgrade

    a1 = create_asset({'hostname': 'FLEET-01', 'ip_address': '10.0.3.1', 'operating_system': 'Linux'})
    a2 = create_asset({'hostname': 'FLEET-02', 'ip_address': '10.0.3.2', 'operating_system': 'Linux'})
    sw = get_or_create_software("Redis", "Redis Ltd")

    inst1 = add_installed_software(a1.id, sw.id, "6.2.0")
    inst2 = add_installed_software(a2.id, sw.id, "6.2.0")

    # Error handling
    with pytest.raises(ValueError, match="Software ID 999999 not found"):
        fleet_wide_software_upgrade(999999, "7.0.0")

    with pytest.raises(ValueError, match="Target version cannot be empty"):
        fleet_wide_software_upgrade(sw.id, "")

    res = fleet_wide_software_upgrade(sw.id, "7.0.0")
    assert res['updated_count'] == 2

    inst1_refreshed = db_get_inst(inst1.id)
    inst2_refreshed = db_get_inst(inst2.id)
    assert inst1_refreshed.version == "7.0.0"
    assert inst2_refreshed.version == "7.0.0"


def db_get_inst(inst_id):
    from epcras.extensions import db
    return db.session.get(InstalledSoftware, inst_id)


