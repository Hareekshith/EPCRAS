from datetime import datetime, timezone
from epcras.extensions import db

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    condition_key = db.Column(db.String(128), nullable=False, index=True)
    title = db.Column(db.String(128), nullable=False)
    message = db.Column(db.String(512), nullable=False)
    severity = db.Column(db.String(16), nullable=False, default='INFO')  # INFO, WARNING, HIGH, CRITICAL
    link_url = db.Column(db.String(256), nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic', cascade='all, delete-orphan'))

    def __repr__(self):
        return f"<Notification id={self.id} key='{self.condition_key}' severity='{self.severity}' is_read={self.is_read}>"
