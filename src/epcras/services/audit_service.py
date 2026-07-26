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
    """Log an audit event to the database."""
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
