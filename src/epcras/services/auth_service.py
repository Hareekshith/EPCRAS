from datetime import datetime, timezone
from functools import wraps
from flask import abort, request
from flask_login import current_user
from epcras.extensions import db
from epcras.models.user import User, LoginHistory
from epcras.services.audit_service import log_audit_event

def authenticate_user(username_or_email: str, password: str, ip_address: str = None, user_agent: str = None):
    """Authenticate a user by username or email and record login history & audit log."""
    if not username_or_email or not password:
        return None, "Username/email and password are required."

    query_str = username_or_email.strip().lower()
    user = User.query.filter(
        (db.func.lower(User.username) == query_str) | 
        (db.func.lower(User.email) == query_str)
    ).first()

    if user and user.is_active and user.check_password(password):
        # Record successful login history
        user.last_login = datetime.now(timezone.utc)
        history = LoginHistory(
            user_id=user.id,
            username=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
            status='SUCCESS'
        )
        db.session.add(history)
        db.session.commit()

        log_audit_event(
            action_category='AUTH',
            username=user.username,
            target_entity='UserSession',
            details='User logged in successfully',
            ip_address=ip_address,
            status='SUCCESS',
            user_id=user.id
        )
        return user, None
    else:
        # Record failed login attempt
        target_username = user.username if user else username_or_email
        history = LoginHistory(
            user_id=user.id if user else None,
            username=target_username,
            ip_address=ip_address,
            user_agent=user_agent,
            status='FAILED'
        )
        db.session.add(history)
        db.session.commit()

        log_audit_event(
            action_category='AUTH',
            username=target_username,
            target_entity='UserSession',
            details='Failed login attempt',
            ip_address=ip_address,
            status='FAILED',
            user_id=user.id if user else None
        )
        error_msg = "Account is inactive." if (user and not user.is_active) else "Invalid username/email or password."
        return None, error_msg

def role_required(*roles):
    """Decorator to enforce Role-Based Access Control on endpoints."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if not current_user.has_role(*roles):
                log_audit_event(
                    action_category='SECURITY',
                    username=current_user.username,
                    target_entity=request.path,
                    details=f"Forbidden access attempt. User role '{current_user.role}' not in required roles {roles}",
                    status='DENIED',
                    user_id=current_user.id
                )
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
