import csv
import io
from datetime import datetime, timezone
from epcras.extensions import db
from epcras.models.software import Software, InstalledSoftware
from epcras.models.asset import Asset, Criticality
from epcras.services.audit_service import log_audit_event

def get_all_software():
    return Software.query.order_by(Software.name.asc(), Software.vendor.asc()).all()

def get_software_by_id(software_id: int) -> Software:
    return db.session.get(Software, software_id)

def get_or_create_software(name: str, vendor: str, category: str = None) -> Software:
    name_clean = name.strip()
    vendor_clean = vendor.strip()

    sw = Software.query.filter(
        db.func.lower(Software.name) == name_clean.lower(),
        db.func.lower(Software.vendor) == vendor_clean.lower()
    ).first()

    if not sw:
        sw = Software(
            name=name_clean,
            vendor=vendor_clean,
            category=category.strip() if category else None
        )
        db.session.add(sw)
        db.session.commit()
    return sw

def add_installed_software(asset_id: int, software_id: int, version: str, installation_date=None) -> InstalledSoftware:
    asset = db.session.get(Asset, asset_id)
    if not asset:
        raise ValueError(f"Asset ID {asset_id} does not exist.")

    sw = db.session.get(Software, software_id)
    if not sw:
        raise ValueError(f"Software ID {software_id} does not exist.")

    version_clean = version.strip()
    existing = InstalledSoftware.query.filter_by(
        asset_id=asset_id,
        software_id=software_id,
        version=version_clean
    ).first()

    if existing:
        return existing

    installed_sw = InstalledSoftware(
        asset_id=asset_id,
        software_id=software_id,
        version=version_clean,
        installation_date=installation_date
    )
    asset.last_inventory_update = datetime.now(timezone.utc)
    db.session.add(installed_sw)
    db.session.commit()

    log_audit_event(
        action_category='SOFTWARE_UPDATED',
        target_entity=f"Asset:{asset.hostname}",
        details=f"Linked software '{sw.name}' ({version_clean}) to asset {asset.hostname}",
        status='SUCCESS'
    )
    return installed_sw

def remove_installed_software(installed_sw_id: int) -> bool:
    installed_sw = db.session.get(InstalledSoftware, installed_sw_id)
    if not installed_sw:
        return False

    asset_hostname = installed_sw.asset.hostname if installed_sw.asset else 'Unknown'
    sw_name = installed_sw.software.name if installed_sw.software else 'Unknown'
    version = installed_sw.version

    db.session.delete(installed_sw)
    db.session.commit()

    log_audit_event(
        action_category='SOFTWARE_UPDATED',
        target_entity=f"Asset:{asset_hostname}",
        details=f"Removed software '{sw_name}' ({version}) from asset {asset_hostname}",
        status='SUCCESS'
    )

    return True

def import_software_csv(file_stream) -> dict:
    """
    Import software inventory from CSV stream.
    Expected CSV header: hostname,software,vendor,version
    """
    errors = []
    success_count = 0

    try:
        content = file_stream.read().decode('utf-8-sig')
        csv_file = io.StringIO(content)
        reader = csv.DictReader(csv_file)
    except Exception as e:
        return {"success_count": 0, "errors": [f"Failed to read CSV file: {str(e)}"]}

    if not reader.fieldnames:
        return {"success_count": 0, "errors": ["CSV file is empty or missing headers."]}

    # Normalize header names (lowercase, strip whitespace)
    field_map = {name.strip().lower(): name for name in reader.fieldnames}
    required_cols = ['hostname', 'software', 'vendor', 'version']
    missing_cols = [col for col in required_cols if col not in field_map]

    if missing_cols:
        return {
            "success_count": 0,
            "errors": [f"CSV missing required columns: {', '.join(missing_cols)}. Expected header: hostname,software,vendor,version"]
        }

    for row_num, row in enumerate(reader, start=2):
        hostname = row.get(field_map['hostname'], '').strip()
        software_name = row.get(field_map['software'], '').strip()
        vendor = row.get(field_map['vendor'], '').strip()
        version = row.get(field_map['version'], '').strip()

        row_errors = []
        if not hostname:
            row_errors.append("hostname is missing")
        if not software_name:
            row_errors.append("software name is missing")
        if not vendor:
            row_errors.append("vendor is missing")
        if not version:
            row_errors.append("version is missing")

        if row_errors:
            errors.append(f"Row {row_num}: {', '.join(row_errors)}.")
            continue

        # Get or create Asset
        asset = Asset.query.filter(db.func.lower(Asset.hostname) == hostname.lower()).first()
        if not asset:
            # Auto-create asset with minimal details for convenience during inventory sync
            asset = Asset(
                hostname=hostname,
                ip_address="127.0.0.1",
                operating_system="Unknown",
                criticality=Criticality.MEDIUM
            )
            db.session.add(asset)
            db.session.flush()

        # Get or create Software
        sw = get_or_create_software(software_name, vendor)

        # Check existing InstalledSoftware
        existing = InstalledSoftware.query.filter_by(
            asset_id=asset.id,
            software_id=sw.id,
            version=version
        ).first()

        if not existing:
            installed = InstalledSoftware(
                asset_id=asset.id,
                software_id=sw.id,
                version=version
            )
            db.session.add(installed)

        asset.last_inventory_update = datetime.now(timezone.utc)
        success_count += 1

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return {"success_count": 0, "errors": [f"Database commit error: {str(e)}"]}

    log_audit_event(
        action_category='SOFTWARE',
        target_entity='CSV_Import',
        details=f"Imported {success_count} software records from CSV. Encountered {len(errors)} row errors.",
        status='SUCCESS' if not errors else 'PARTIAL'
    )

    return {"success_count": success_count, "errors": errors}
