from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from epcras.models.user import Role
from epcras.services.auth_service import role_required

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard/index.html')

@main_bp.route('/admin-only')
@login_required
@role_required(Role.ADMINISTRATOR)
def admin_only():
    return "Admin Only Access Granted"

@main_bp.route('/analyst-only')
@login_required
@role_required(Role.ADMINISTRATOR, Role.SECURITY_ANALYST)
def analyst_only():
    return "Analyst Access Granted"
