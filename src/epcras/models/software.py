from datetime import datetime, timezone
from epcras.extensions import db

class Software(db.Model):
    __tablename__ = 'software'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    vendor = db.Column(db.String(128), nullable=False)
    category = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        db.UniqueConstraint('name', 'vendor', name='uq_software_name_vendor'),
    )

    installations = db.relationship('InstalledSoftware', backref='software', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Software id={self.id} name='{self.name}' vendor='{self.vendor}'>"

class InstalledSoftware(db.Model):
    __tablename__ = 'installed_software'

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    software_id = db.Column(db.Integer, db.ForeignKey('software.id'), nullable=False)
    version = db.Column(db.String(50), nullable=False)
    installation_date = db.Column(db.Date, nullable=True)
    compliance_status = db.Column(db.String(32), default='Unknown', nullable=False)  # Compliant, Non-Compliant, Unpatched Risk, Unknown
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        db.UniqueConstraint('asset_id', 'software_id', 'version', name='uq_asset_software_version'),
    )

    def __repr__(self):
        return f"<InstalledSoftware asset_id={self.asset_id} software_id={self.software_id} version='{self.version}'>"
