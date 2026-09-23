import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, redirect, url_for, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from epcras.config import config_by_name
from epcras.extensions import db, login_manager, csrf
from epcras.models.user import User
from epcras.routes.auth import auth_bp
from epcras.routes.main import main_bp
from epcras.routes.asset import asset_bp
from epcras.routes.software import software_bp
from epcras.routes.vulnerability import vulnerability_bp
from epcras.routes.compliance import compliance_bp
from epcras.routes.report import report_bp
from epcras.routes.search import search_bp
from epcras.routes.notification import notification_bp
from epcras.routes.admin import admin_bp
from epcras.cli import register_cli_commands

def configure_logging(app):
    """Configure structured logging for stdout and optional rotating file handler."""
    log_level_name = app.config.get('LOG_LEVEL', 'INFO').upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    app.logger.setLevel(log_level)

    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )

    # Avoid duplicate handlers during testing or reload
    if not app.logger.handlers:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(log_level)
        app.logger.addHandler(stream_handler)

    log_file = app.config.get('LOG_FILE')
    if log_file:
        try:
            log_dir = os.path.dirname(os.path.abspath(log_file))
            os.makedirs(log_dir, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_file, maxBytes=10 * 1024 * 1024, backupCount=5
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            app.logger.addHandler(file_handler)
        except OSError as e:
            app.logger.warning(f"Could not initialize log file at {log_file}: {e}")

def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'development')

    app = Flask(__name__, instance_relative_config=True)
    cfg_class = config_by_name[config_name]
    app.config.from_object(cfg_class)

    # Validate production configuration
    if hasattr(cfg_class, 'check_config'):
        cfg_class.check_config()

    # Configure Logging
    configure_logging(app)

    # Apply ProxyFix middleware for reverse proxy deployments (e.g. Nginx)
    if app.config.get('USE_PROXY_FIX', False):
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=app.config.get('PROXY_FIX_FOR', 1),
            x_proto=app.config.get('PROXY_FIX_PROTO', 1),
            x_host=app.config.get('PROXY_FIX_HOST', 1),
            x_prefix=app.config.get('PROXY_FIX_PREFIX', 1)
        )
        app.logger.info("ProxyFix middleware enabled for reverse-proxy deployment.")

    # Ensure instance and database directories exist
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if db_uri.startswith('sqlite:///'):
            db_path = db_uri.replace('sqlite:///', '')
            if db_path and db_path != ':memory:':
                os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    except OSError as e:
        app.logger.warning(f"Could not create database directory: {e}")

    # Initialize Extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # User Loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Global Template Context Processor for Notifications
    @app.context_processor
    def inject_notifications():
        from flask_login import current_user
        from epcras.services.notification_service import get_unread_count
        if current_user.is_authenticated:
            return {'unread_notifications_count': get_unread_count(current_user.id)}
        return {'unread_notifications_count': 0}

    # Error Handlers
    @app.errorhandler(401)
    def unauthorized_error(error):
        flash('Unauthorized access. Please log in.', 'warning')
        return redirect(url_for('auth.login'))

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.error(f"Unhandled Internal Server Error: {error}", exc_info=True)
        return render_template('errors/500.html'), 500

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(asset_bp)
    app.register_blueprint(software_bp)
    app.register_blueprint(vulnerability_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(notification_bp)
    app.register_blueprint(admin_bp)

    # Register CLI Commands
    register_cli_commands(app)

    return app
