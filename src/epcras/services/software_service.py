import csv
import io
import re
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


def clean_fixed_version(fixed_version_str: str) -> str:
    """Extract a clean target version from a fixed_version string (e.g. '>= 2.17.1' -> '2.17.1')."""
    if not fixed_version_str:
        return ""
    clean = fixed_version_str.strip()
    if ',' in clean:
        clean = clean.split(',')[0].strip()
    clean = re.sub(r'^[><=~^v\s]+', '', clean).strip()
    return clean


def update_installed_software_version(installed_sw_id: int, new_version: str, trigger_compliance: bool = True) -> dict:
    """
    Update the version of an installed software record on an asset.
    Automatically handles duplicate resolution, updates timestamp, and re-scans compliance.
    """
    installed_sw = db.session.get(InstalledSoftware, installed_sw_id)
    if not installed_sw:
        raise ValueError(f"Installed software record ID {installed_sw_id} not found.")

    new_version_clean = new_version.strip() if new_version else ""
    if not new_version_clean:
        raise ValueError("New software version cannot be empty.")

    asset = installed_sw.asset
    sw = installed_sw.software
    old_version = installed_sw.version
    asset_id = installed_sw.asset_id
    software_id = installed_sw.software_id

    # If already at that version, re-scan compliance and return
    if old_version == new_version_clean:
        if trigger_compliance:
            from epcras.services.compliance_service import run_compliance_analysis
            run_compliance_analysis(asset_id=asset_id)
        return {
            'success': True,
            'installed_sw_id': installed_sw.id,
            'asset_id': asset_id,
            'asset_hostname': asset.hostname if asset else 'Unknown',
            'software_name': sw.name if sw else 'Unknown',
            'old_version': old_version,
            'new_version': new_version_clean,
            'already_updated': True
        }

    # Check if this asset already has another record with the target version
    existing_target = InstalledSoftware.query.filter_by(
        asset_id=asset_id,
        software_id=software_id,
        version=new_version_clean
    ).first()

    if existing_target and existing_target.id != installed_sw.id:
        db.session.delete(installed_sw)
        target_record_id = existing_target.id
    else:
        installed_sw.version = new_version_clean
        installed_sw.updated_at = datetime.now(timezone.utc)
        target_record_id = installed_sw.id

    if asset:
        asset.last_inventory_update = datetime.now(timezone.utc)

    db.session.commit()

    log_audit_event(
        action_category='SOFTWARE_UPDATED',
        target_entity=f"Asset:{asset.hostname if asset else 'Unknown'}",
        details=f"Updated software '{sw.name if sw else 'Unknown'}' from version '{old_version}' to '{new_version_clean}' on asset {asset.hostname if asset else 'Unknown'}",
        status='SUCCESS'
    )

    if trigger_compliance:
        from epcras.services.compliance_service import run_compliance_analysis
        run_compliance_analysis(asset_id=asset_id)

    return {
        'success': True,
        'installed_sw_id': target_record_id,
        'asset_id': asset_id,
        'asset_hostname': asset.hostname if asset else 'Unknown',
        'software_name': sw.name if sw else 'Unknown',
        'old_version': old_version,
        'new_version': new_version_clean,
        'already_updated': False
    }


def bulk_patch_findings(finding_ids: list = None, patch_all_fixable: bool = False) -> dict:
    """
    Bulk update vulnerable software installations to their fixed versions.
    If patch_all_fixable is True, updates all non-compliant findings that have a fixed_version.
    If finding_ids is provided, updates only the specified finding records.
    """
    from epcras.models.compliance import ComplianceResult, ComplianceStatus
    from epcras.services.compliance_service import run_compliance_analysis

    query = ComplianceResult.query.filter_by(status=ComplianceStatus.NON_COMPLIANT)
    if not patch_all_fixable:
        if not finding_ids:
            return {"updated_count": 0, "affected_assets_count": 0, "errors": ["No findings selected for bulk update."]}
        query = query.filter(ComplianceResult.id.in_(finding_ids))

    findings = query.all()
    if not findings:
        return {"updated_count": 0, "affected_assets_count": 0, "errors": ["No eligible non-compliant findings found."]}

    updated_count = 0
    affected_assets = set()
    errors = []
    processed_installations = set()

    for finding in findings:
        if not finding.fixed_version:
            continue

        target_version = clean_fixed_version(finding.fixed_version)
        if not target_version:
            continue

        installed_sw_id = finding.installed_software_id
        if installed_sw_id in processed_installations:
            continue

        try:
            update_installed_software_version(
                installed_sw_id=installed_sw_id,
                new_version=target_version,
                trigger_compliance=False
            )
            processed_installations.add(installed_sw_id)
            affected_assets.add(finding.asset_id)
            updated_count += 1
        except Exception as e:
            errors.append(f"Failed updating finding ID {finding.id}: {str(e)}")

    if updated_count > 0:
        for aid in affected_assets:
            run_compliance_analysis(asset_id=aid)

        log_audit_event(
            action_category='BULK_PATCH',
            target_entity='ComplianceRemediation',
            details=f"Bulk patched {updated_count} software installations across {len(affected_assets)} asset(s).",
            status='SUCCESS'
        )

    return {
        "updated_count": updated_count,
        "affected_assets_count": len(affected_assets),
        "errors": errors
    }


def fleet_wide_software_upgrade(software_id: int, target_version: str, current_version: str = None) -> dict:
    """
    Upgrade all installations of a software product to a target version across all assets in the organization.
    Optionally filter by current_version (e.g. only upgrade assets running 2.4.49).
    """
    from epcras.services.compliance_service import run_compliance_analysis

    sw = db.session.get(Software, software_id)
    if not sw:
        raise ValueError(f"Software ID {software_id} not found.")

    target_version_clean = target_version.strip() if target_version else ""
    if not target_version_clean:
        raise ValueError("Target version cannot be empty.")

    query = InstalledSoftware.query.filter_by(software_id=software_id)
    if current_version and current_version.strip():
        query = query.filter_by(version=current_version.strip())

    installations = query.all()
    if not installations:
        return {
            "software_name": sw.name,
            "target_version": target_version_clean,
            "updated_count": 0,
            "affected_assets_count": 0
        }

    updated_count = 0
    affected_assets = set()

    for item in installations:
        if item.version == target_version_clean:
            continue
        try:
            update_installed_software_version(
                installed_sw_id=item.id,
                new_version=target_version_clean,
                trigger_compliance=False
            )
            affected_assets.add(item.asset_id)
            updated_count += 1
        except Exception:
            pass

    if updated_count > 0:
        for aid in affected_assets:
            run_compliance_analysis(asset_id=aid)

        log_audit_event(
            action_category='FLEET_SOFTWARE_UPGRADE',
            target_entity=f"Software:{sw.name}",
            details=f"Fleet-wide upgrade: Updated {updated_count} installation(s) of '{sw.name}' to version '{target_version_clean}' across {len(affected_assets)} asset(s).",
            status='SUCCESS'
        )

    return {
        "software_name": sw.name,
        "target_version": target_version_clean,
        "updated_count": updated_count,
        "affected_assets_count": len(affected_assets)
    }

