from datetime import datetime, timezone
from sqlalchemy import or_
from epcras.extensions import db
from epcras.models.asset import Asset, Department, Criticality
from epcras.models.software import InstalledSoftware, Software
from epcras.services.audit_service import log_audit_event

def get_all_assets(search_query: str = None, criticality: str = None, department_id: int = None, asset_type: str = None):
    """Retrieve filtered and searched asset query list."""
    query = Asset.query

    if criticality:
        query = query.filter(Asset.criticality == criticality)

    if department_id:
        query = query.filter(Asset.department_id == department_id)

    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)

    if search_query:
        term = f"%{search_query.strip()}%"
        query = query.outerjoin(Asset.department)\
                     .outerjoin(Asset.installed_software)\
                     .outerjoin(InstalledSoftware.software)\
                     .filter(
                         or_(
                             Asset.hostname.ilike(term),
                             Asset.ip_address.ilike(term),
                             Asset.operating_system.ilike(term),
                             Asset.owner.ilike(term),
                             Department.name.ilike(term),
                             Software.name.ilike(term),
                             Software.vendor.ilike(term)
                         )
                     ).distinct()

    return query.order_by(Asset.hostname.asc()).all()

def get_asset_by_id(asset_id: int) -> Asset:
    return db.session.get(Asset, asset_id)

def get_asset_by_hostname(hostname: str) -> Asset:
    if not hostname:
        return None
    return Asset.query.filter(db.func.lower(Asset.hostname) == hostname.strip().lower()).first()

def create_asset(data: dict) -> Asset:
    """Create a new IT asset."""
    hostname = (data.get('hostname') or '').strip()
    if get_asset_by_hostname(hostname):
        raise ValueError(f"An asset with hostname '{hostname}' already exists.")

    os_ver = (data.get('os_version') or '').strip()
    owner_val = (data.get('owner') or '').strip()

    asset = Asset(
        hostname=hostname,
        ip_address=(data.get('ip_address') or '').strip(),
        operating_system=(data.get('operating_system') or '').strip(),
        os_version=os_ver if os_ver else None,
        department_id=data.get('department_id') or None,
        owner=owner_val if owner_val else None,
        asset_type=data.get('asset_type', 'Workstation'),
        criticality=data.get('criticality', Criticality.MEDIUM),
        last_inventory_update=datetime.now(timezone.utc)
    )
    db.session.add(asset)
    db.session.commit()

    log_audit_event(
        action_category='ASSET_CREATED',
        target_entity=f"Asset:{asset.hostname}",
        details=f"Created asset {asset.hostname} (IP: {asset.ip_address}, Criticality: {asset.criticality})",
        status='SUCCESS'
    )
    return asset

def update_asset(asset_id: int, data: dict) -> Asset:
    """Update an existing IT asset."""
    asset = get_asset_by_id(asset_id)
    if not asset:
        raise ValueError(f"Asset ID {asset_id} not found.")

    new_hostname = (data.get('hostname') or '').strip()
    if new_hostname and new_hostname.lower() != asset.hostname.lower():
        if get_asset_by_hostname(new_hostname):
            raise ValueError(f"An asset with hostname '{new_hostname}' already exists.")
        asset.hostname = new_hostname
    elif new_hostname and new_hostname != asset.hostname:
        asset.hostname = new_hostname

    os_ver = (data.get('os_version') or '').strip()
    owner_val = (data.get('owner') or '').strip()

    asset.ip_address = (data.get('ip_address') or asset.ip_address).strip()
    asset.operating_system = (data.get('operating_system') or asset.operating_system).strip()
    asset.os_version = os_ver if os_ver else None
    asset.department_id = data.get('department_id', asset.department_id) or None
    asset.owner = owner_val if owner_val else None
    asset.asset_type = data.get('asset_type', asset.asset_type)
    asset.criticality = data.get('criticality', asset.criticality)
    asset.last_inventory_update = datetime.now(timezone.utc)

    db.session.commit()

    log_audit_event(
        action_category='ASSET_UPDATED',
        target_entity=f"Asset:{asset.hostname}",
        details=f"Updated asset metadata for {asset.hostname}",
        status='SUCCESS'
    )
    return asset

def delete_asset(asset_id: int) -> bool:
    """Delete an IT asset."""
    asset = get_asset_by_id(asset_id)
    if not asset:
        return False

    hostname = asset.hostname
    db.session.delete(asset)
    db.session.commit()

    log_audit_event(
        action_category='ASSET_DELETED',
        target_entity=f"Asset:{hostname}",
        details=f"Deleted asset {hostname} (ID: {asset_id})",
        status='SUCCESS'
    )
    return True


def get_all_departments():
    return Department.query.order_by(Department.name.asc()).all()

def create_department(name: str, description: str = None) -> Department:
    name_clean = name.strip()
    existing = Department.query.filter(db.func.lower(Department.name) == name_clean.lower()).first()
    if existing:
        return existing

    dept = Department(name=name_clean, description=description.strip() if description else None)
    db.session.add(dept)
    db.session.commit()

    log_audit_event(
        action_category='DEPARTMENT',
        target_entity=f"Department:{name_clean}",
        details=f"Created department {name_clean}",
        status='SUCCESS'
    )
    return dept
