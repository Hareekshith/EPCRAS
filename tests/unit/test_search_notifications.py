import pytest
from epcras.models.user import User, Role
from epcras.models.asset import Asset, Criticality
from epcras.models.compliance import ComplianceResult, ComplianceStatus
from epcras.models.notification import Notification
from epcras.services.asset_service import create_asset, create_department
from epcras.services.software_service import get_or_create_software, add_installed_software
from epcras.services.vulnerability_service import create_vulnerability
from epcras.services.compliance_service import run_compliance_analysis
from epcras.services.search_service import search_system
from epcras.services.notification_service import (
    create_notification, get_user_notifications, get_unread_count, mark_as_read, mark_all_as_read
)

def test_centralized_search_multi_parameters(app):
    dept = create_department("Finance", "Finance Dept")
    asset = create_asset({'hostname': 'FIN-SERVER-01', 'ip_address': '192.168.10.5', 'department_id': dept.id, 'criticality': Criticality.HIGH})
    sw = get_or_create_software("Log4j", "Apache")
    add_installed_software(asset.id, sw.id, "2.14.0")

    create_vulnerability({
        'cve_id': 'CVE-2021-44228',
        'software': 'Log4j',
        'vendor': 'Apache',
        'cvss_score': 10.0,
        'severity': 'CRITICAL',
        'affected_versions': '2.0 <= 2.14.1',
        'fixed_version': '2.17.1'
    })
    run_compliance_analysis()

    # Search by hostname
    res = search_system({'hostname': 'FIN-SERVER'})
    assert res['total'] >= 1
    assert any('FIN-SERVER-01' in item['title'] for item in res['results_list'])


    # Search by IP
    res = search_system({'ip_address': '192.168.10.5'})
    assert res['total'] >= 1

    # Search by department
    res = search_system({'department': 'Finance'})
    assert res['total'] >= 1

    # Search by software
    res = search_system({'software': 'Log4j'})
    assert res['total'] >= 1

    # Search by CVE
    res = search_system({'cve_id': '44228'})
    assert res['total'] >= 1

    # Search by severity
    res = search_system({'severity': 'CRITICAL'})
    assert res['total'] >= 1

    # Search by compliance status
    res = search_system({'compliance_status': 'NON_COMPLIANT'})
    assert res['total'] >= 1

    # Search by asset criticality
    res = search_system({'criticality': 'HIGH'})
    assert res['total'] >= 1

def test_notification_creation_and_deduplication(app):
    key = "TEST_CONDITION:123"

    # First notification creation
    n1 = create_notification(key, "Test Title", "Test Message", severity="HIGH")
    assert n1.id is not None
    assert get_unread_count() == 1

    # Duplicate creation with SAME key -> suppressed
    n2 = create_notification(key, "Test Title", "Test Message", severity="HIGH")
    assert n2.id == n1.id
    assert get_unread_count() == 1  # Unchanged!

    # Mark as read
    assert mark_as_read(n1.id) is True
    assert get_unread_count() == 0

    # New notification for same key AFTER previous is read -> creates new notification
    n3 = create_notification(key, "Test Title 2", "Test Message 2", severity="HIGH")
    assert n3.id != n1.id
    assert get_unread_count() == 1

def test_mark_all_notifications_read(app):
    create_notification("COND1", "Title 1", "Msg 1")
    create_notification("COND2", "Title 2", "Msg 2")
    create_notification("COND3", "Title 3", "Msg 3")

    assert get_unread_count() == 3
    count = mark_all_as_read()
    assert count == 3
    assert get_unread_count() == 0

def test_critical_vulnerability_triggers_notification(app):
    vuln = create_vulnerability({
        'cve_id': 'CVE-2024-3094',
        'software': 'xz-utils',
        'vendor': 'Tukaani',
        'cvss_score': 10.0,
        'severity': 'CRITICAL'
    })

    notifs = get_user_notifications(is_read=False)
    assert len(notifs) >= 1
    assert any('CVE-2024-3094' in n.title for n in notifs)

def test_non_compliant_asset_triggers_notification(app):
    asset = create_asset({'hostname': 'VULN-ASSET', 'ip_address': '10.0.0.99'})
    sw = get_or_create_software("Log4j", "Apache")
    add_installed_software(asset.id, sw.id, "2.14.0")

    create_vulnerability({
        'cve_id': 'CVE-2021-44228',
        'software': 'Log4j',
        'vendor': 'Apache',
        'cvss_score': 10.0,
        'severity': 'CRITICAL',
        'affected_versions': '2.0 <= 2.14.1',
        'fixed_version': '2.17.1'
    })

    run_compliance_analysis()
    notifs = get_user_notifications(is_read=False)
    assert any('VULN-ASSET' in n.title for n in notifs)

def test_notification_user_isolation(app, admin_user, analyst_user):
    # Private notification for admin
    n_admin = create_notification("KEY_ADMIN", "Admin Alert", "Only for admin", user_id=admin_user.id)
    # Broadcast notification
    n_broadcast = create_notification("KEY_ALL", "System Alert", "For all users", user_id=None)

    # Admin sees both
    admin_notifs = get_user_notifications(user_id=admin_user.id)
    admin_ids = [n.id for n in admin_notifs]
    assert n_admin.id in admin_ids
    assert n_broadcast.id in admin_ids

    # Analyst sees broadcast but NOT admin's private notification
    analyst_notifs = get_user_notifications(user_id=analyst_user.id)
    analyst_ids = [n.id for n in analyst_notifs]
    assert n_broadcast.id in analyst_ids
    assert n_admin.id not in analyst_ids

    # Analyst cannot mark admin's private notification as read
    assert mark_as_read(n_admin.id, user_id=analyst_user.id) is False
    assert mark_as_read(999999, user_id=analyst_user.id) is False

    # Admin CAN mark their own notification as read
    assert mark_as_read(n_admin.id, user_id=admin_user.id) is True

def test_search_system_pagination_and_vuln_branch(app):
    create_vulnerability({
        'cve_id': 'CVE-2024-SEARCH-1',
        'software': 'SearchSoft',
        'vendor': 'VendorS',
        'cvss_score': 9.5,
        'severity': 'CRITICAL'
    })
    create_vulnerability({
        'cve_id': 'CVE-2024-SEARCH-2',
        'software': 'SearchSoft',
        'vendor': 'VendorS',
        'cvss_score': 7.0,
        'severity': 'HIGH'
    })

    # Search purely for vulnerabilities (no asset criteria)
    res = search_system({'cve_id': 'SEARCH', 'software': 'SearchSoft'}, page=1, per_page=1)
    assert res['total'] == 2
    assert len(res['results_list']) == 1
    assert res['pages'] == 2
    assert res['page'] == 1
    assert res['results_list'][0]['type'] == 'VULNERABILITY'

    # Out of range page
    res_empty = search_system({'cve_id': 'SEARCH'}, page=10, per_page=10)
    assert len(res_empty['results_list']) == 0

def test_notification_repr(app):
    n = Notification(condition_key='REPR_KEY', title='Repr', message='Msg', severity='HIGH', is_read=False)
    assert 'REPR_KEY' in repr(n)
    assert 'HIGH' in repr(n)

