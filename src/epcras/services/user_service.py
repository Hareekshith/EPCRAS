from typing import List, Optional
from epcras.extensions import db
from epcras.models.user import User, Role
from epcras.services.audit_service import log_audit_event

def get_all_users(search: str = None, role: str = None, is_active: Optional[bool] = None) -> List[User]:
    """Retrieve users with optional filtering."""
    query = User.query

    if search:
        search_clean = search.strip()
        query = query.filter(
            (User.username.ilike(f"%{search_clean}%")) |
            (User.email.ilike(f"%{search_clean}%"))
        )

    if role and role.upper() in Role.all_roles():
        query = query.filter(User.role == role.upper())

    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    return query.order_by(User.username.asc()).all()

def get_user_by_id(user_id: int) -> Optional[User]:
    return db.session.get(User, user_id)

def get_user_by_username(username: str) -> Optional[User]:
    if not username:
        return None
    return User.query.filter(db.func.lower(User.username) == username.strip().lower()).first()

def create_user(data: dict) -> User:
    """Create a new user account and log USER_CREATED audit event."""
    username = data.get('username', '').strip()
    if not username:
        raise ValueError("Username is required.")

    email = data.get('email', '').strip().lower()
    if not email:
        raise ValueError("Email is required.")

    password = data.get('password', '')
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")

    role = data.get('role', Role.IT_SUPPORT).strip().upper()
    if role not in Role.all_roles():
        raise ValueError(f"Invalid role '{role}'.")

    # Uniqueness checks
    if User.query.filter(db.func.lower(User.username) == username.lower()).first():
        raise ValueError(f"Username '{username}' is already in use.")

    if User.query.filter(db.func.lower(User.email) == email.lower()).first():
        raise ValueError(f"Email '{email}' is already in use.")

    user = User(
        username=username,
        email=email,
        role=role,
        is_active=bool(data.get('is_active', True))
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    log_audit_event(
        action_category='USER_CREATED',
        target_entity=f"User:{user.username}",
        details=f"Created user account '{user.username}' with role '{user.role}'",
        status='SUCCESS'
    )

    return user

def update_user(user_id: int, data: dict) -> User:
    """Update user email, role, active status or password and log USER_UPDATED audit event."""
    user = db.session.get(User, user_id)
    if not user:
        raise ValueError(f"User ID {user_id} does not exist.")

    email = data.get('email', '').strip().lower()
    if not email:
        raise ValueError("Email is required.")

    # Uniqueness check for email
    existing_email = User.query.filter(
        db.func.lower(User.email) == email.lower(),
        User.id != user_id
    ).first()
    if existing_email:
        raise ValueError(f"Email '{email}' is already used by another account.")

    role = data.get('role', user.role).strip().upper()
    if role not in Role.all_roles():
        raise ValueError(f"Invalid role '{role}'.")

    password = data.get('password', '')
    if password and len(password) >= 8:
        user.set_password(password)

    user.email = email
    user.role = role
    user.is_active = bool(data.get('is_active', user.is_active))

    db.session.commit()

    log_audit_event(
        action_category='USER_UPDATED',
        target_entity=f"User:{user.username}",
        details=f"Updated user account '{user.username}' (Role: {user.role}, Active: {user.is_active})",
        status='SUCCESS'
    )

    return user

def toggle_user_active_status(user_id: int) -> bool:
    """Toggle user active status (enable/disable account)."""
    user = db.session.get(User, user_id)
    if not user:
        raise ValueError(f"User ID {user_id} does not exist.")

    user.is_active = not user.is_active
    db.session.commit()

    status_str = "ENABLED" if user.is_active else "DISABLED"
    log_audit_event(
        action_category='USER_UPDATED',
        target_entity=f"User:{user.username}",
        details=f"User account '{user.username}' was {status_str}",
        status='SUCCESS'
    )

    return user.is_active
