from typing import Optional, List
from epcras.extensions import db
from epcras.models.notification import Notification

def create_notification(condition_key: str, title: str, message: str, severity: str = 'INFO', link_url: str = None, user_id: int = None) -> Notification:
    """
    Create an in-app notification with condition-based deduplication.
    If an unread notification with identical condition_key already exists, creation is suppressed.
    """
    condition_clean = condition_key.strip()
    
    # Check for existing unread notification for the same condition
    query = Notification.query.filter_by(condition_key=condition_clean, is_read=False)
    if user_id is not None:
        query = query.filter((Notification.user_id == user_id) | (Notification.user_id.is_(None)))
    
    existing = query.first()
    if existing:
        return existing  # Suppress duplicate notification for unchanged condition

    notif = Notification(
        user_id=user_id,
        condition_key=condition_clean,
        title=title.strip(),
        message=message.strip(),
        severity=severity.upper(),
        link_url=link_url.strip() if link_url else None,
        is_read=False
    )

    db.session.add(notif)
    db.session.commit()
    return notif

def get_user_notifications(user_id: int = None, is_read: Optional[bool] = None, limit: int = 50) -> List[Notification]:
    """Retrieve in-app notifications for user or broadcast notifications."""
    query = Notification.query
    if user_id is not None:
        query = query.filter((Notification.user_id == user_id) | (Notification.user_id.is_(None)))

    if is_read is not None:
        query = query.filter(Notification.is_read == is_read)

    return query.order_by(Notification.created_at.desc()).limit(limit).all()

def get_unread_count(user_id: int = None) -> int:
    """Get count of unread in-app notifications."""
    query = Notification.query.filter_by(is_read=False)
    if user_id is not None:
        query = query.filter((Notification.user_id == user_id) | (Notification.user_id.is_(None)))
    return query.count()

def mark_as_read(notification_id: int, user_id: int = None) -> bool:
    """Mark a single notification as read."""
    notif = db.session.get(Notification, notification_id)
    if not notif:
        return False

    notif.is_read = True
    db.session.commit()
    return True

def mark_all_as_read(user_id: int = None) -> int:
    """Mark all unread notifications as read."""
    query = Notification.query.filter_by(is_read=False)
    if user_id is not None:
        query = query.filter((Notification.user_id == user_id) | (Notification.user_id.is_(None)))

    count = 0
    for notif in query.all():
        notif.is_read = True
        count += 1

    db.session.commit()
    return count
