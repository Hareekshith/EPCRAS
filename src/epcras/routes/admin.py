from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from epcras.extensions import db
from epcras.models.user import User, Role
from epcras.models.asset import Asset, Department
from epcras.models.vulnerability import Vulnerability
from epcras.models.audit import AuditLog
from epcras.services.auth_service import role_required
from epcras.services.user_service import (
    get_all_users, get_user_by_id, create_user, update_user, toggle_user_active_status
)
from epcras.services.audit_service import get_audit_logs
from epcras.forms.admin_forms import UserCreateForm, UserEditForm

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.before_request
@login_required
@role_required(Role.ADMINISTRATOR)
def enforce_admin_access():
    """Ensure all administrative endpoints enforce Administrator authorization server-side."""
    pass

@admin_bp.route('/')
def index():
    """System Overview Dashboard for Administrators."""
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_assets = Asset.query.count()
    total_vulnerabilities = Vulnerability.query.count()
    total_audit_logs = AuditLog.query.count()
    total_departments = Department.query.count()

    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(5).all()

    return render_template(
        'admin/index.html',
        total_users=total_users,
        active_users=active_users,
        total_assets=total_assets,
        total_vulnerabilities=total_vulnerabilities,
        total_audit_logs=total_audit_logs,
        total_departments=total_departments,
        recent_logs=recent_logs
    )

@admin_bp.route('/users')
def users():
    """User Management List."""
    search = request.args.get('search', '').strip()
    role_filter = request.args.get('role', '').strip()
    status_filter = request.args.get('status', '').strip()

    is_active_param = None
    if status_filter == 'active':
        is_active_param = True
    elif status_filter == 'disabled':
        is_active_param = False

    user_list = get_all_users(search=search, role=role_filter, is_active=is_active_param)

    return render_template(
        'admin/users.html',
        users=user_list,
        roles=Role.all_roles(),
        search=search,
        selected_role=role_filter,
        selected_status=status_filter
    )

@admin_bp.route('/users/new', methods=['GET', 'POST'])
def create_user_route():
    """Create User Account."""
    form = UserCreateForm()
    if form.validate_on_submit():
        try:
            user = create_user({
                'username': form.username.data,
                'email': form.email.data,
                'password': form.password.data,
                'role': form.role.data,
                'is_active': form.is_active.data
            })
            flash(f"User account '{user.username}' created successfully.", 'success')
            return redirect(url_for('admin.users'))
        except ValueError as e:
            flash(str(e), 'danger')
    elif request.method == 'POST':
        for field, errs in form.errors.items():
            flash(f"{field}: {', '.join(errs)}", 'danger')

    return render_template('admin/user_form.html', form=form, title="Create User Account", is_edit=False)

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
def edit_user_route(user_id):
    """Edit User Account & Role Assignment."""
    user = get_user_by_id(user_id)
    if not user:
        flash('User account not found.', 'danger')
        return redirect(url_for('admin.users'))

    form = UserEditForm(obj=user)
    form.username.data = user.username

    if form.validate_on_submit():
        try:
            update_user(user_id, {
                'email': form.email.data,
                'role': form.role.data,
                'is_active': form.is_active.data,
                'password': form.password.data
            })
            flash(f"User account '{user.username}' updated successfully.", 'success')
            return redirect(url_for('admin.users'))
        except ValueError as e:
            flash(str(e), 'danger')
    elif request.method == 'POST':
        for field, errs in form.errors.items():
            flash(f"{field}: {', '.join(errs)}", 'danger')



    return render_template('admin/user_form.html', form=form, title=f"Edit User: {user.username}", is_edit=True, user=user)



@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
def toggle_status(user_id):
    """Enable / Disable User Account."""
    if current_user.id == user_id:
        flash("You cannot disable your own active administrator account.", 'warning')
        return redirect(url_for('admin.users'))

    try:
        is_active = toggle_user_active_status(user_id)
        status_text = "enabled" if is_active else "disabled"
        flash(f"User account has been {status_text}.", 'info')
    except ValueError as e:
        flash(str(e), 'danger')

    return redirect(url_for('admin.users'))

@admin_bp.route('/audit-logs')
def audit_logs():
    """Audit Log Viewer."""
    action_category = request.args.get('action_category', '').strip()
    username = request.args.get('username', '').strip()
    search = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)

    log_data = get_audit_logs(
        action_category=action_category,
        username=username,
        search=search,
        page=page,
        per_page=25
    )

    action_categories = [
        'LOGIN', 'LOGOUT', 'ASSET_CREATED', 'ASSET_UPDATED', 'ASSET_DELETED',
        'SOFTWARE_UPDATED', 'CVE_IMPORTED', 'COMPLIANCE_SCAN', 'REPORT_GENERATED',
        'USER_CREATED', 'USER_UPDATED', 'DEPARTMENT', 'VULN'
    ]

    return render_template(
        'admin/audit_logs.html',
        log_data=log_data,
        action_categories=action_categories,
        selected_category=action_category,
        username_query=username,
        search_query=search
    )
