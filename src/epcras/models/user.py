from datetime import datetime, timezone
from enum import Enum
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from epcras.extensions import db

class Role:
    ADMINISTRATOR = 'ADMINISTRATOR'
    SECURITY_ANALYST = 'SECURITY_ANALYST'
    IT_SUPPORT = 'IT_SUPPORT'
    AUDITOR = 'AUDITOR'

    @classmethod
    def choices(cls):
        return [
            (cls.ADMINISTRATOR, 'Administrator'),
            (cls.SECURITY_ANALYST, 'Security Analyst'),
            (cls.IT_SUPPORT, 'IT Support'),
            (cls.AUDITOR, 'Auditor'),
        ]

    @classmethod
    def all_roles(cls):
        return [cls.ADMINISTRATOR, cls.SECURITY_ANALYST, cls.IT_SUPPORT, cls.AUDITOR]

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), nullable=False, default=Role.IT_SUPPORT)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    login_history = db.relationship('LoginHistory', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles: str) -> bool:
        """Check if user has any of the specified roles."""
        return self.role in roles

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMINISTRATOR

    def __repr__(self):
        return f"<User id={self.id} username='{self.username}' role='{self.role}'>"

class LoginHistory(db.Model):
    __tablename__ = 'login_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # 'SUCCESS', 'FAILED'
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<LoginHistory username='{self.username}' status='{self.status}' at={self.timestamp}>"
