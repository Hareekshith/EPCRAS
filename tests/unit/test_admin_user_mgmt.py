import pytest
from epcras.models.user import User, Role
from epcras.models.audit import AuditLog
from epcras.services.user_service import (
    create_user, update_user, toggle_user_active_status, get_all_users, get_user_by_id, get_user_by_username
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

def test_create_user_validation_failures(app):
    # Empty username
    with pytest.raises(ValueError, match="Username is required"):
        create_user({'username': '', 'email': 'valid@test.com', 'password': 'Password123!'})

    # Empty email
    with pytest.raises(ValueError, match="Email is required"):
        create_user({'username': 'validuser', 'email': '', 'password': 'Password123!'})

    # Password too short (<8)
    with pytest.raises(ValueError, match="Password must be at least 8 characters"):
        create_user({'username': 'validuser', 'email': 'valid@test.com', 'password': 'short'})

    # Invalid role
    with pytest.raises(ValueError, match="Invalid role"):
        create_user({'username': 'validuser', 'email': 'valid@test.com', 'password': 'Password123!', 'role': 'HACKER'})

def test_get_user_by_username_and_id(app):
    user = create_user({'username': 'FindMe', 'email': 'findme@test.com', 'password': 'Password123!'})
    assert get_user_by_username('findme').id == user.id
    assert get_user_by_username('FINDME').id == user.id
    assert get_user_by_username('') is None
    assert get_user_by_username(None) is None

    assert get_user_by_id(user.id).username == 'FindMe'
    assert get_user_by_id(999999) is None

def test_update_user_validation_and_password(app):
    user = create_user({'username': 'pass_update', 'email': 'pass@test.com', 'password': 'OldPassword123!'})

    # Non-existent user
    with pytest.raises(ValueError, match="does not exist"):
        update_user(999999, {'email': 'some@test.com'})

    # Empty email
    with pytest.raises(ValueError, match="Email is required"):
        update_user(user.id, {'email': ''})

    # Invalid role
    with pytest.raises(ValueError, match="Invalid role"):
        update_user(user.id, {'email': 'pass@test.com', 'role': 'SUPERUSER'})

    # Retaining own email succeeds
    updated = update_user(user.id, {'email': 'pass@test.com', 'role': Role.SECURITY_ANALYST})
    assert updated.role == Role.SECURITY_ANALYST

    # Duplicate email with another user
    other = create_user({'username': 'other_u', 'email': 'other@test.com', 'password': 'Password123!'})
    with pytest.raises(ValueError, match="already used"):
        update_user(user.id, {'email': 'other@test.com'})

    # Password update with >= 8 characters
    update_user(user.id, {'email': 'pass@test.com', 'password': 'NewBrandPassword123!'})
    assert user.check_password('NewBrandPassword123!') is True
    assert user.check_password('OldPassword123!') is False

def test_toggle_nonexistent_user(app):
    with pytest.raises(ValueError, match="does not exist"):
        toggle_user_active_status(999999)

def test_get_all_users_filtering(app):
    create_user({'username': 'alice_it', 'email': 'alice@company.com', 'password': 'Password123!', 'role': Role.IT_SUPPORT, 'is_active': True})
    create_user({'username': 'bob_sec', 'email': 'bob@company.com', 'password': 'Password123!', 'role': Role.SECURITY_ANALYST, 'is_active': False})
    create_user({'username': 'charlie_audit', 'email': 'charlie@other.com', 'password': 'Password123!', 'role': Role.AUDITOR, 'is_active': True})

    # Search filter
    assert len(get_all_users(search='alice')) == 1
    assert len(get_all_users(search='company.com')) == 2

    # Role filter
    assert len(get_all_users(role=Role.AUDITOR)) == 1
    assert len(get_all_users(role='IT_SUPPORT')) == 1

    # Active filter
    assert len(get_all_users(is_active=False)) == 1
    assert get_all_users(is_active=False)[0].username == 'bob_sec'


