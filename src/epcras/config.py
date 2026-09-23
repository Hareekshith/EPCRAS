import os
import warnings
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file if available
load_dotenv()

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production-epcras-2026')
    PROJECT_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f"sqlite:///{os.path.join(PROJECT_ROOT, 'instance', 'epcras.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session Security & Inactive Expiration
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('SESSION_LIFETIME_MINUTES', 30)))
    SESSION_PROTECTION = 'strong'
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = int(os.environ.get('WTF_CSRF_TIME_LIMIT', 3600))

    # Secure Cookie Settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ('true', '1', 'yes')
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ('true', '1', 'yes')

    # Logging and Reverse Proxy
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', None)
    USE_PROXY_FIX = os.environ.get('USE_PROXY_FIX', 'false').lower() in ('true', '1', 'yes')
    PROXY_FIX_FOR = int(os.environ.get('PROXY_FIX_FOR', 1))
    PROXY_FIX_PROTO = int(os.environ.get('PROXY_FIX_PROTO', 1))
    PROXY_FIX_HOST = int(os.environ.get('PROXY_FIX_HOST', 1))
    PROXY_FIX_PREFIX = int(os.environ.get('PROXY_FIX_PREFIX', 1))

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    TESTING = False
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False  # Disabled during automated tests for convenience
    PRESERVE_CONTEXT_ON_EXCEPTION = False

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    TESTING = False
    USE_PROXY_FIX = os.environ.get('USE_PROXY_FIX', 'true').lower() in ('true', '1', 'yes')
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

    @classmethod
    def check_config(cls):
        secret = os.environ.get('SECRET_KEY')
        if not secret or secret == 'dev-secret-key-change-in-production-epcras-2026':
            warnings.warn(
                "SECURITY WARNING: Production is running with a default or missing SECRET_KEY! "
                "Set a unique, high-entropy SECRET_KEY in your environment or .env file.",
                RuntimeWarning,
                stacklevel=2
            )

config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
