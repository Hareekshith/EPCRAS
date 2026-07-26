from datetime import datetime, timezone
from epcras.extensions import db

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(64), nullable=False)
    action_category = db.Column(db.String(64), nullable=False)  # AUTH, ASSET, VULN, USER_MGMT, SYSTEM
    target_entity = db.Column(db.String(128), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.String(512), nullable=True)
    status = db.Column(db.String(20), default='SUCCESS', nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self):
        return f"<AuditLog id={self.id} user='{self.username}' category='{self.action_category}' timestamp={self.timestamp}>"
