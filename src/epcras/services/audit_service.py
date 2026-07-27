import math
from flask import request
from flask_login import current_user
from epcras.extensions import db
from epcras.models.audit import AuditLog

def log_audit_event(
    action_category: str,
    username: str = None,
    target_entity: str = None,
    details: str = None,
    ip_address: str = None,
    status: str = 'SUCCESS',
    user_id: int = None
) -> AuditLog:
    """Log an audit event to the database. Secrets (passwords, tokens) must never be logged."""
    if username is None and current_user and current_user.is_authenticated:
        username = current_user.username
        user_id = user_id or current_user.id
    elif username is None:
        username = 'SYSTEM/ANONYMOUS'

    if ip_address is None:
        try:
            ip_address = request.remote_addr
        except RuntimeError:
            ip_address = '127.0.0.1'

    entry = AuditLog(
        user_id=user_id,
        username=username,
        action_category=action_category,
        target_entity=target_entity,
        ip_address=ip_address,
        details=details,
        status=status
    )
    db.session.add(entry)
    db.session.commit()
    return entry

def get_audit_logs(action_category: str = None, username: str = None, search: str = None, page: int = 1, per_page: int = 25) -> dict:
    """Query paginated audit logs for viewer with filtering."""
    query = AuditLog.query

    if action_category:
        query = query.filter(AuditLog.action_category == action_category.strip().upper())

    if username:
        query = query.filter(AuditLog.username.ilike(f"%{username.strip()}%"))

    if search:
        search_clean = search.strip()
        query = query.filter(
            (AuditLog.target_entity.ilike(f"%{search_clean}%")) |
            (AuditLog.details.ilike(f"%{search_clean}%")) |
            (AuditLog.ip_address.ilike(f"%{search_clean}%"))
        )

    total = query.count()
    page = max(1, int(page))
    per_page = max(1, int(per_page))
    pages = math.ceil(total / per_page) if total > 0 else 1

    logs = query.order_by(AuditLog.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return {
        "logs_list": logs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages
    }

