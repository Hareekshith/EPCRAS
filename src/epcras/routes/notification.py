from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from epcras.services.notification_service import (
    get_user_notifications, mark_as_read, mark_all_as_read, get_unread_count
)

notification_bp = Blueprint('notification', __name__, url_prefix='/notifications')

@notification_bp.route('/', methods=['GET'])
@login_required
def index():
    filter_read = request.args.get('is_read')
    is_read_param = None
    if filter_read == 'true':
        is_read_param = True
    elif filter_read == 'false':
        is_read_param = False

    notifications = get_user_notifications(user_id=current_user.id, is_read=is_read_param, limit=100)
    unread_count = get_unread_count(user_id=current_user.id)

    return render_template(
        'notifications/index.html',
        notifications=notifications,
        unread_count=unread_count,
        filter_read=filter_read
    )

@notification_bp.route('/<int:notification_id>/read', methods=['POST'])
@login_required
def read_single(notification_id):
    if mark_as_read(notification_id, user_id=current_user.id):
        flash('Notification marked as read.', 'success')
    return redirect(request.referrer or url_for('notification.index'))

@notification_bp.route('/read-all', methods=['POST'])
@login_required
def read_all():
    count = mark_all_as_read(user_id=current_user.id)
    flash(f'Marked {count} notifications as read.', 'info')
    return redirect(url_for('notification.index'))
