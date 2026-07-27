import pytest
from epcras.models.user import User, Role
from epcras.models.audit import AuditLog
from epcras.services.user_service import (
    create_user, update_user, toggle_user_active_status, get_all_users, get_user_by_id
)
from epcras.services.audit_service import log_audit_event, get_audit_logs

def test_create_user_service(app):
    user = create_user({
        'username': 'new_analyst',
        'email': 'analyst@epcras.local',
        'password': 'Password123!',
        'role': Role.SECURITY_ANALYST,
        'is_active': True
    })

    assert user.id is not None
    assert user.username == 'new_analyst'
    assert user.role == Role.SECURITY_ANALYST
    assert user.check_password('Password123!') is True

    # Audit log check
    log = AuditLog.query.filter_by(action_category='USER_CREATED', target_entity='User:new_analyst').first()
    assert log is not None

def test_create_duplicate_user_fails(app):
    create_user({
        'username': 'unique_user',
        'email': 'unique@epcras.local',
        'password': 'Password123!',
        'role': Role.IT_SUPPORT
    })

    with pytest.raises(ValueError, match="Username 'unique_user' is already in use."):
        create_user({
            'username': 'unique_user',
            'email': 'other@epcras.local',
            'password': 'Password123!',
            'role': Role.IT_SUPPORT
        })

    with pytest.raises(ValueError, match="Email 'unique@epcras.local' is already in use."):
        create_user({
            'username': 'other_user',
            'email': 'unique@epcras.local',
            'password': 'Password123!',
            'role': Role.IT_SUPPORT
        })

def test_update_user_role_and_status(app):
    user = create_user({
        'username': 'user_to_update',
        'email': 'update@epcras.local',
        'password': 'Password123!',
        'role': Role.AUDITOR
    })

    updated = update_user(user.id, {
        'email': 'updated_email@epcras.local',
        'role': Role.SECURITY_ANALYST,
        'is_active': False
    })

    assert updated.email == 'updated_email@epcras.local'
    assert updated.role == Role.SECURITY_ANALYST
    assert updated.is_active is False

    log = AuditLog.query.filter_by(action_category='USER_UPDATED', target_entity='User:user_to_update').first()
    assert log is not None

def test_toggle_user_active_status(app):
    user = create_user({
        'username': 'toggle_user',
        'email': 'toggle@epcras.local',
        'password': 'Password123!',
        'role': Role.IT_SUPPORT,
        'is_active': True
    })

    active = toggle_user_active_status(user.id)
    assert active is False

    active_again = toggle_user_active_status(user.id)
    assert active_again is True

def test_get_audit_logs_query(app):
    log_audit_event('LOGIN', username='user1', target_entity='AuthSystem', details='Logged in successfully')
    log_audit_event('CVE_IMPORTED', username='admin1', target_entity='CVE-2024-3094', details='Imported 5 records')

    res1 = get_audit_logs(action_category='LOGIN')
    assert res1['total'] >= 1
    assert all(l.action_category == 'LOGIN' for l in res1['logs_list'])

    res2 = get_audit_logs(search='3094')
    assert res2['total'] >= 1
    assert any('CVE-2024-3094' in l.target_entity for l in res2['logs_list'])

