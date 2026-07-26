import os
from flask import Flask, render_template, redirect, url_for, flash
from epcras.config import config_by_name
from epcras.extensions import db, login_manager, csrf
from epcras.models.user import User
from epcras.routes.auth import auth_bp
from epcras.routes.main import main_bp
from epcras.routes.asset import asset_bp
from epcras.routes.software import software_bp
from epcras.cli import register_cli_commands

def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'development')

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_by_name[config_name])

    # Ensure instance and database directories exist
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if db_uri.startswith('sqlite:///'):
            db_path = db_uri.replace('sqlite:///', '')
            if db_path and db_path != ':memory:':
                os.makedirs(os.path.dirname(db_path), exist_ok=True)
    except OSError:
        pass

    # Initialize Extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # User Loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

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
        return render_template('errors/500.html'), 500

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(asset_bp)
    app.register_blueprint(software_bp)

    # Register CLI Commands
    register_cli_commands(app)

    return app
