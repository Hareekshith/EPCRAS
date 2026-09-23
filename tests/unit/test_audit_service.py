import pytest
from epcras.models.audit import AuditLog
from epcras.services.audit_service import log_audit_event, get_audit_logs

def test_log_audit_event_explicit_fields(app):
    entry = log_audit_event(
        action_category='TEST_ACTION',
        username='auditor_bob',
        target_entity='Asset:PC-01',
        details='Modified network config',
        ip_address='192.168.1.50',
        status='SUCCESS',
        user_id=42
    )

    assert entry.id is not None
    assert entry.action_category == 'TEST_ACTION'
    assert entry.username == 'auditor_bob'
    assert entry.target_entity == 'Asset:PC-01'
    assert entry.details == 'Modified network config'
    assert entry.ip_address == '192.168.1.50'
    assert entry.status == 'SUCCESS'
    assert entry.user_id == 42
    assert entry.timestamp is not None

def test_log_audit_event_anonymous_and_default_ip(app):
    # Outside of request context and without current_user
    entry = log_audit_event(
        action_category='SYSTEM_TASK',
        details='Nightly synchronization'
    )

    assert entry.username == 'SYSTEM/ANONYMOUS'
    assert entry.ip_address == '127.0.0.1'
    assert entry.status == 'SUCCESS'

def test_audit_logs_query_filtering_and_pagination(app):
    # Seed 15 logs
    for i in range(10):
        log_audit_event(
            action_category='ASSET_AUDIT',
            username=f'user_{i % 3}',
            target_entity=f'Entity-{i}',
            details=f'Detail event {i}',
            ip_address=f'10.0.0.{i}'
        )
    for i in range(5):
        log_audit_event(
            action_category='VULN_AUDIT',
            username='cve_admin',
            target_entity=f'CVE-2024-{i}',
            details=f'Vulnerability imported {i}',
            ip_address='10.1.1.1'
        )

    # Filter by category
    res_cat = get_audit_logs(action_category='ASSET_AUDIT')
    assert res_cat['total'] == 10
    assert all(l.action_category == 'ASSET_AUDIT' for l in res_cat['logs_list'])

    # Filter by username
    res_user = get_audit_logs(username='cve_admin')
    assert res_user['total'] == 5
    assert all(l.username == 'cve_admin' for l in res_user['logs_list'])

    # Search query in details or target_entity
    res_search = get_audit_logs(search='CVE-2024')
    assert res_search['total'] == 5

    # Pagination
    res_p1 = get_audit_logs(page=1, per_page=5)
    assert len(res_p1['logs_list']) == 5
    assert res_p1['page'] == 1
    assert res_p1['pages'] >= 3

    res_p2 = get_audit_logs(page=2, per_page=5)
    assert len(res_p2['logs_list']) == 5
    assert res_p2['page'] == 2

def test_audit_log_repr(app):
    log = AuditLog(
        username='audit_repr_user',
        action_category='TEST_REPR',
        status='SUCCESS'
    )
    r = repr(log)
    assert 'audit_repr_user' in r
    assert 'TEST_REPR' in r
