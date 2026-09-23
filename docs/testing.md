# EPCRAS Comprehensive Testing Documentation

This document describes the testing strategy, test categories, major test cases, defects discovered and resolved, and the final verification results for the **Enterprise Patch Compliance and Risk Assessment System (EPCRAS)**.

---

## 1. Testing Strategy

### 1.1 Objectives and Scope
The EPCRAS testing strategy establishes deterministic verification across all system layers without altering product specifications or redesigning working modules. The primary objectives are:
- **Functional Integrity**: Verify business rules for asset tracking, software cataloguing, vulnerability correlation, compliance calculation, priority scoring, reporting, and audit logging.
- **Security & Authorization**: Enforce strict server-side Role-Based Access Control (RBAC) across all user roles (`ADMINISTRATOR`, `SECURITY_ANALYST`, `IT_SUPPORT`, `AUDITOR`) and anonymous visitors.
- **Robustness & Input Validation**: Test boundary conditions, malformed files, malicious inputs (SQL Injection, XSS, Path Traversal, Open Redirects), and oversized payloads.
- **Lifecycle Integration**: Verify complete operational workflows linking asset provisioning, software inventory association, CVE ingestion, compliance scans, patch prioritization, and report exports.

### 1.2 Test Architecture & Environment
- **Framework**: `pytest >= 8.0.0`
- **Database Isolation**: SQLite in-memory (`sqlite:///:memory:`) configured in `TestingConfig`, reinitialized with fresh schemas (`db.create_all()` / `db.drop_all()`) per test fixture.
- **Client Fixtures**:
  - `app`: Configured application context in test mode with CSRF enabled or test-managed.
  - `client`: Flask test client simulating HTTP sessions and cookies.
  - `runner`: Flask CLI runner for command testing (e.g., `seed-admin`).
  - Pre-seeded role fixtures: `admin_user`, `analyst_user`, `support_user`, `auditor_user`.

```
                    +------------------------------------+
                    |     End-to-End Workflow Tests      |
                    | (Asset -> Soft -> Vuln -> Comp ->  |
                    |        Priority -> Reports)        |
                    +------------------------------------+
                    |   Security & Malicious Input Tests |
                    | (SQLi, XSS, Path Traversal, Redir) |
                    +------------------------------------+
                    |       Integration Route Tests      |
                    | (RBAC Matrix, Admin, Asset, Vuln)  |
                    +------------------------------------+
                    |         Service Unit Tests         |
                    | (Version Utils, Scoring, Analytics)|
                    +------------------------------------+
```

---

## 2. Test Categories

The suite is divided into focused unit and integration modules:

### 2.1 Unit Tests (`tests/unit/`)
| Module | Scope / Focus |
| :--- | :--- |
| `test_auth.py` | Password hashing, case-insensitive authentication, login history recording, inactive accounts, CLI commands. |
| `test_admin_user_mgmt.py` | User CRUD service, password updates, duplicate checks, role validations, account status toggles. |
| `test_asset.py` | Asset creation, hostname uniqueness, case-only renames, department linkage, cascading deletion to software and compliance records. |
| `test_software.py` | Software catalogue deduplication, asset linking, CSV import handling (UTF-8, BOM, missing headers, row errors). |
| `test_vulnerability.py` | Vulnerability creation, CVSS range checks (0.0–10.0), severity choices, CSV import formats, dates (`YYYY-MM-DD`, `MM/DD/YYYY`, `DD-MM-YYYY`), booleans. |
| `test_version_utils.py` | Semantic versioning, multi-part versions, OpenSSL trailing letters (`1.1.1f`), discrete lists (`5.6.0, 5.6.1`), ranges (`to`, `-`, `<=`, `>=`), explicit OR (`or`, `\|`). |
| `test_compliance.py` | Automated version correlation against CVEs, single-asset vs organization-wide scans, unknown version handling, aggregate summary metrics. |
| `test_priority_engine.py` | Deterministic 0–100 composite scoring, factor point breakdowns (CVSS 35%, Criticality 25%, Exploit 15%, Assets 10%, Age 10%, Patch 5%), priority tiers, queue ordering. |
| `test_search_notifications.py` | Multi-parameter search, notification creation, condition-key deduplication, user isolation, read status tracking. |
| `test_dashboard_reports.py` | Real-time database metrics derivation, department distribution with unassigned groups, CSV and PDF report generation across all 5 report types. |
| `test_audit_service.py` | Immutable audit logging, request IP detection, anonymous actor fallback, category and search filtering, pagination. |

### 2.2 Integration Tests (`tests/integration/`)
| Module | Scope / Focus |
| :--- | :--- |
| `test_rbac_matrix.py` | Exhaustive role permission matrix across Admin, Asset, Software, Vulnerability, Compliance, and Report endpoints for all 4 roles + unauthenticated users. |
| `test_auth_routes.py` | Login web flow, session persistence, logout flow, safe relative redirects, open redirect defense, error handlers (`401`, `403`, `404`, `500`). |
| `test_admin_routes.py` | Admin dashboard overview, user creation, editing roles, disabling accounts, audit log viewer filtering. |
| `test_asset_routes.py` | Asset CRUD web forms, software association and disassociation, department creation, non-existent entity error redirects. |
| `test_vulnerability_routes.py` | Vulnerability database browsing, administrative create/edit/delete, detail views, CSV file uploads. |
| `test_compliance_routes.py` | Manual scan triggers (single-asset and global), non-compliant exposure list with severity/software filters, asset compliance details, patch priority queue UI. |
| `test_report_routes.py` | Report center interface, CSV file downloads, ReportLab PDF streaming, invalid report type and format rejection. |
| `test_search_notification_routes.py` | Search interface execution, in-app notification list, marking single and all notifications as read. |
| `test_malicious_input.py` | SQL injection resilience, XSS escaping in Jinja2, path traversal attempts in reports, open redirect vectors, oversized payloads, corrupt CSV uploads, admin self-disable prevention. |
| `test_workflow_e2e.py` | Complete security operations lifecycle from asset provisioning to PDF compliance report generation. |

---

## 3. Major Test Cases

### 3.1 End-to-End Enterprise Workflow (`test_workflow_e2e.py`)
- **Workflow Steps**:
  1. Administrator authenticates via `/auth/login`.
  2. Creates a department (`Core Infrastructure`).
  3. Provisions two assets:
     - `PROD-DB-01` (`Criticality.CRITICAL`, Server, IP `10.50.1.10`)
     - `WS-DEV-01` (`Criticality.LOW`, Workstation, IP `10.50.2.15`)
  4. Associates software installations:
     - `PROD-DB-01` linked with `OpenSSL 1.1.1f` (vulnerable) and `curl 7.68.0` (vulnerable).
     - `WS-DEV-01` linked with `OpenSSL 1.1.1w` (patched).
  5. Ingests vulnerabilities:
     - `CVE-2021-3711` (OpenSSL, CVSS 9.8, CRITICAL, affected `< 1.1.1l`, fixed `1.1.1l`, exploit=True, patch=True).
     - `CVE-2023-38545` (curl, CVSS 9.8, CRITICAL, affected `< 8.4.0`, fixed `8.4.0`, exploit=True, patch=True).
  6. Executes organization-wide compliance scan via `POST /compliance/run`.
  7. **Assertions**:
     - `PROD-DB-01` status evaluates to `Non-Compliant` with 2 findings.
     - `WS-DEV-01` status evaluates to `Compliant`.
     - In-app high-severity notifications generated for `PROD-DB-01` and both critical CVEs.
  8. Evaluates `/compliance/priority`:
     - Both CVEs score in the `CRITICAL` priority tier.
  9. Validates `/dashboard` metrics:
     - 2 total assets, 1 compliant (50.0% compliance rate), critical vulnerabilities counted.
  10. Generates and downloads `OVERALL_COMPLIANCE`, `PATCH_PRIORITY`, and `CRITICAL_VULNERABILITY` reports in CSV and PDF.
  11. Verifies audit log trail records: `AUTH`, `DEPARTMENT`, `ASSET_CREATED`, `SOFTWARE_UPDATED`, `VULN`, and `COMPLIANCE_SCAN`.

### 3.2 Role-Based Access Control Matrix (`test_rbac_matrix.py`)
- **Matrix Verification**:
  - `/admin/*`: Administrator (200), Security Analyst (403), IT Support (403), Auditor (403), Anonymous (302).
  - `/assets/` & `/assets/<id>`: Administrator (200), Security Analyst (200), IT Support (200), Auditor (200), Anonymous (302).
  - `/assets/new`, `/assets/<id>/edit`, `/assets/<id>/delete`, `/assets/departments`: Administrator (200), IT Support (200), Security Analyst (403), Auditor (403).
  - `/software/`: All roles (200).
  - `/software/new`, `/software/import`: Administrator (200), IT Support (200), Security Analyst (403), Auditor (403).
  - `/vulnerabilities/` & `/vulnerabilities/<id>`: Administrator (200), Security Analyst (200), IT Support (403), Auditor (403).
  - `/vulnerabilities/new`, `/vulnerabilities/<id>/edit`, `/vulnerabilities/<id>/delete`, `/vulnerabilities/import`: Administrator (200), Security Analyst (403), IT Support (403), Auditor (403).
  - `/compliance/run` (POST): Administrator (302), Security Analyst (302), IT Support (302), Auditor (403).
  - `/reports/*`: All authenticated roles (200).

### 3.3 Security & Adversarial Input Cases (`test_malicious_input.py`)
- **SQL Injection**: Payloads (`' OR '1'='1`, `'; DROP TABLE users; --`, `' UNION SELECT ...`, `admin' --`) submitted across search parameters and audit queries execute safely without syntax errors or data exposure.
- **Cross-Site Scripting (XSS)**: Payload `<script>alert('EPCRAS_XSS')</script>` injected in asset metadata and vulnerability descriptions is HTML-escaped (`&lt;script&gt;alert(&#39;EPCRAS_XSS&#39;)&lt;/script&gt;`), neutralizing script execution.
- **Path Traversal**: Payloads (`../../etc/passwd`, `..%2F..%2Fetc%2Fpasswd`, `/etc/shadow`) sent to report export routes are safely rejected (`404` or redirect) without leaking system files.
- **Open Redirect**: Vectors (`//malicious.com`, `/\\malicious.com`, `https://attacker.com`, `javascript:alert(1)`) supplied via `next` query parameter during login are caught and redirected safely to internal `/dashboard`.
- **Oversized Payloads**: 5,000-character string in hostname field is rejected by form length validators.
- **Admin Self-Disable**: Administrator attempting to disable their own account via `POST /admin/users/<id>/toggle-status` is prevented with a warning message.

---

## 4. Defects Discovered and Resolved

During test expansion, several critical defects were uncovered and fixed:

1. **Version Range Evaluation for Discrete Lists & OR Clauses (`src/epcras/utils/version.py`)**:
   - *Defect*: `is_version_in_range` split clauses by comma and evaluated using `all(...)`. For discrete lists (e.g. `'5.6.0, 5.6.1'`), requiring a version to equal both `5.6.0` AND `5.6.1` resulted in false negatives (`False`).
   - *Fix*: Detect expressions with explicit OR (`or`, `|`) or comma-separated lists of exact versions, switching evaluation to `any(...)` while preserving `all(...)` for relational range bounds (`>= 2.0, <= 2.14.1`).

2. **OpenSSL Trailing Letter Precedence (`src/epcras/utils/version.py`)**:
   - *Defect*: `parse_version` invoked `packaging_parse` before checking OpenSSL letter patch levels. `packaging_parse` treated `1.1.1a` and `1.1.1b` as alpha pre-releases (`1.1.1a0 < 1.1.1`), breaking OpenSSL release sequencing.
   - *Fix*: Prioritized `letter_patch_match` before fallback `packaging_parse`, converting trailing letters `a-z` to patch integers (`1.1.1.1` through `1.1.1.26`), restoring proper ordering.

3. **Protocol-Relative Open Redirect in Auth Route (`src/epcras/routes/auth.py`)**:
   - *Defect*: The redirect validation `if next_page and next_page.startswith('/'):` allowed protocol-relative URLs such as `//evil.com` or `/\\evil.com`.
   - *Fix*: Enhanced validation to `if next_page and next_page.startswith('/') and not next_page.startswith('//') and not next_page.startswith('/\\'):`.

4. **Missing Ownership Check in Notification Read Action (`src/epcras/services/notification_service.py`)**:
   - *Defect*: `mark_as_read(notification_id, user_id)` received `user_id` but did not enforce ownership, allowing one user to mark another user's private notification as read.
   - *Fix*: Added verification: `if user_id is not None and notif.user_id is not None and notif.user_id != user_id: return False`.

5. **Hostname Casing Update Bug (`src/epcras/services/asset_service.py`)**:
   - *Defect*: `update_asset` checked `if new_hostname.lower() != asset.hostname.lower():`, ignoring case-only updates (`WEB-01` to `web-01`).
   - *Fix*: Handled case updates while retaining duplicate collision prevention against different assets.

6. **NoneType Crash on Optional Fields in Vulnerability Creation/Update (`src/epcras/services/vulnerability_service.py`)**:
   - *Defect*: Calling `data.get('affected_versions', '').strip()` when WTForms passed `None` raised `AttributeError: 'NoneType' object has no attribute 'strip'`.
   - *Fix*: Replaced with `(data.get('affected_versions') or '').strip() or None` across `create_vulnerability` and `update_vulnerability`.

---

## 5. Test Suite Execution & Results

### 5.1 Test Execution Command
```bash
pytest -v
```

### 5.2 Results Breakdown
```
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /home/htarizzs/Github/EPCRAS
collected 153 items

tests/integration/test_admin_routes.py .....                             [  3%]
tests/integration/test_asset_routes.py ......                            [  7%]
tests/integration/test_auth_routes.py ..........                         [ 13%]
tests/integration/test_compliance_routes.py .....                        [ 16%]
tests/integration/test_malicious_input.py ........                       [ 22%]
tests/integration/test_rbac_matrix.py ......                             [ 26%]
tests/integration/test_report_routes.py ....                             [ 28%]
tests/integration/test_search_notification_routes.py ....                [ 31%]
tests/integration/test_vulnerability_routes.py ......                    [ 35%]
tests/integration/test_workflow_e2e.py .                                 [ 35%]
tests/unit/test_admin_user_mgmt.py ..........                            [ 42%]
tests/unit/test_asset.py .......                                         [ 47%]
tests/unit/test_audit_service.py ....                                    [ 49%]
tests/unit/test_auth.py .............                                    [ 58%]
tests/unit/test_compliance.py ..........                                 [ 64%]
tests/unit/test_dashboard_reports.py .......                             [ 69%]
tests/unit/test_priority_engine.py .......                               [ 73%]
tests/unit/test_search_notifications.py ........                         [ 79%]
tests/unit/test_software.py .........                                    [ 84%]
tests/unit/test_version_utils.py ............                            [ 92%]
tests/unit/test_vulnerability.py ...........                             [100%]

============================= 153 passed in 28.23s =============================
```

### 5.3 Summary Metrics
- **Total Tests Collected**: 153
- **Passed**: 153
- **Failed**: 0
- **Skipped**: 0
- **Errors**: 0
- **Pass Rate**: 100%
- **Execution Time**: ~28 seconds
