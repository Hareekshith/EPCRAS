from datetime import datetime, timezone
from epcras.extensions import db

class Criticality:
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'

    @classmethod
    def choices(cls):
        return [
            (cls.LOW, 'Low'),
            (cls.MEDIUM, 'Medium'),
            (cls.HIGH, 'High'),
            (cls.CRITICAL, 'Critical'),
        ]

    @classmethod
    def all_levels(cls):
        return [cls.LOW, cls.MEDIUM, cls.HIGH, cls.CRITICAL]

class Department(db.Model):
    __tablename__ = 'departments'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False, index=True)
    description = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    assets = db.relationship('Asset', backref='department', lazy='dynamic')

    def __repr__(self):
        return f"<Department id={self.id} name='{self.name}'>"

class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(128), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    operating_system = db.Column(db.String(100), nullable=False)
    os_version = db.Column(db.String(50), nullable=True)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=True)
    owner = db.Column(db.String(100), nullable=True)
    asset_type = db.Column(db.String(50), default='Workstation', nullable=False)
    criticality = db.Column(db.String(20), default=Criticality.MEDIUM, nullable=False)
    last_inventory_update = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    installed_software = db.relationship('InstalledSoftware', backref='asset', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def department_name(self) -> str:
        return self.department.name if self.department else 'Unassigned'

    def __repr__(self):
        return f"<Asset id={self.id} hostname='{self.hostname}' criticality='{self.criticality}'>"
