from datetime import datetime, timezone
from epcras.extensions import db

class ComplianceStatus:
    COMPLIANT = 'COMPLIANT'
    NON_COMPLIANT = 'NON_COMPLIANT'
    UNKNOWN = 'UNKNOWN'

    @classmethod
    def all_statuses(cls):
        return [cls.COMPLIANT, cls.NON_COMPLIANT, cls.UNKNOWN]

class ComplianceResult(db.Model):
    __tablename__ = 'compliance_results'

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False, index=True)
    installed_software_id = db.Column(db.Integer, db.ForeignKey('installed_software.id'), nullable=False, index=True)
    software_name = db.Column(db.String(128), nullable=False)
    installed_version = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(32), nullable=False, default=ComplianceStatus.UNKNOWN, index=True)
    
    # Vulnerability details for NON_COMPLIANT findings
    cve_id = db.Column(db.String(32), nullable=True, index=True)
    cvss_score = db.Column(db.Float, nullable=True)
    severity = db.Column(db.String(16), nullable=True)
    fixed_version = db.Column(db.String(128), nullable=True)
    patch_available = db.Column(db.Boolean, nullable=True)
    
    scanned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    asset = db.relationship('Asset', backref=db.backref('compliance_results', lazy='dynamic', cascade='all, delete-orphan'))
    installed_software = db.relationship('InstalledSoftware', backref=db.backref('compliance_results', lazy='dynamic', cascade='all, delete-orphan'))

    def __repr__(self):
        return f"<ComplianceResult id={self.id} asset_id={self.asset_id} status='{self.status}' cve='{self.cve_id}'>"
