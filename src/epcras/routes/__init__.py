from .auth import auth_bp
from .main import main_bp
from .asset import asset_bp
from .software import software_bp
from .vulnerability import vulnerability_bp
from .compliance import compliance_bp
from .report import report_bp
from .search import search_bp
from .notification import notification_bp
from .admin import admin_bp

__all__ = [
    'auth_bp', 'main_bp', 'asset_bp', 'software_bp',
    'vulnerability_bp', 'compliance_bp', 'report_bp',
    'search_bp', 'notification_bp', 'admin_bp'
]





