from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from epcras.forms.auth_forms import LoginForm
from epcras.services.auth_service import authenticate_user
from epcras.services.audit_service import log_audit_event

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        ip_addr = request.remote_addr
        user_agent = str(request.user_agent)
        user, error = authenticate_user(
            username_or_email=form.username_or_email.data,
            password=form.password.data,
            ip_address=ip_addr,
            user_agent=user_agent
        )

        if user:
            login_user(user, remember=form.remember_me.data)
            session.permanent = True
            flash(f'Welcome back, {user.username} ({user.role})!', 'success')
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/') and not next_page.startswith('//') and not next_page.startswith('/\\'):
                return redirect(next_page)
            return redirect(url_for('main.dashboard'))
        else:
            flash(error or 'Invalid credentials.', 'danger')

    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    username = current_user.username
    user_id = current_user.id
    logout_user()
    log_audit_event(
        action_category='AUTH',
        username=username,
        target_entity='UserSession',
        details='User logged out',
        status='SUCCESS',
        user_id=user_id
    )
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
