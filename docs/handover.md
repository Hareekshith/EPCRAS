# EPCRAS System Handover & Operational Maintenance Manual

**Project Name:** Enterprise Patch Compliance and Risk Assessment System (EPCRAS)  
**Document Version:** 1.0.0  
**Date of Handover:** September 23, 2026  
**Audience:** System Administrators, Security Engineers, DevOps Engineers, and Academic Evaluators

---

## 1. System Overview

### 1.1 Purpose and Problem Statement
Enterprise cybersecurity requires continuous situational awareness regarding which organizational IT assets run vulnerable or outdated software. Traditional vulnerability management tools are often expensive, complex to deploy, resource-heavy, and opaque in how they rank vulnerabilities for patching.

The **Enterprise Patch Compliance and Risk Assessment System (EPCRAS)** provides an auditable, lightweight, and deterministic solution. It correlates installed software versions against published CVE advisories, computes an explainable 0–100 risk-based priority score, and produces executive dashboards and multi-format compliance reports.

### 1.2 Core Architectural Principles
- **Monolithic & Self-Contained**: Implemented as a modular Python/Flask application without distributed microservices, message queues, Docker, or Kubernetes dependencies.
- **Low-Resource Compatibility**: Engineered to operate comfortably on standard low-resource Linux systems (1 vCPU, 1 GB RAM, 10 GB storage).
- **Deterministic & Auditable**: All version comparison operations use PEP 440 semantic parsing, and patch scoring follows a transparent, mathematical formula without stochastic heuristics.
- **Defense-in-Depth**: Strict server-side Role-Based Access Control (RBAC), CSRF protection, secure cookie flags (`HttpOnly`, `SameSite=Lax`), and immutable audit logging.

---

## 2. System Modules & Functional Architecture

```
                                  +---------------------------------------+
                                  |            Web Browser / UI           |
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |         EPCRAS Application Core       |
+--------------------------+      |                                       |      +--------------------------+
|  Authentication & RBAC   | <--> |  - Blueprints & Routes                | <--> |  Asset & Software Mgmt   |
|  - PBKDF2/scrypt Hashing |      |  - WTForms Validation Layer           |      |  - Asset CRUD & Depts    |
|  - 4 Distinct Roles      |      |  - SQLAlchemy ORM Layer               |      |  - Software Inventory    |
+--------------------------+      +---------------------------------------+      +--------------------------+
             ^                                        ^                                        ^
             |                                        |                                        |
+--------------------------+      +---------------------------------------+      +--------------------------+
|   Vulnerability Engine   | <--> |       Patch Compliance Engine         | <--> |   Priority Engine        |
|   - CVE Database         |      |       - PEP 440 Version Parser        |      |   - 0–100 Weighted Score |
|   - CVSS v3.1 Metrics    |      |       - Relational & Discrete Ranges  |      |   - 4 Actionable Tiers   |
+--------------------------+      +---------------------------------------+      +--------------------------+
             ^                                        ^                                        ^
             |                                        |                                        |
+--------------------------+      +---------------------------------------+      +--------------------------+
|   Executive Dashboard    | <--> |           Reporting Center            | <--> |  Audit Logging & Alerts  |
|   - Real-time Analytics  |      |           - Multi-Format CSV          |      |  - Immutable Audit Trail |
|   - Distribution Charts  |      |           - ReportLab Styled PDF      |      |  - In-App Notifications  |
+--------------------------+      +---------------------------------------+      +--------------------------+
```

### Module Breakdown:

1. **Authentication & Session Management (`epcras.services.auth_service`, `epcras.routes.auth`)**:
   - Secure authentication supporting username or email interchangeably.
   - Passwords hashed using PBKDF2 with SHA-256 (via Werkzeug security).
   - Session duration defaults to 30 minutes of inactivity; session fixation prevented with Flask-Login session renewal.
   - Comprehensive login history records remote IP, user-agent, and status (`SUCCESS`, `FAILED`, `ACCOUNT_INACTIVE`).

2. **Role-Based Access Control (`epcras.models.user.Role`, `@role_required`)**:
   - Server-side role enforcement via decorator `@role_required(...)` on all non-public endpoints.
   - `ADMINISTRATOR`: Full administrative control, user provisioning, vulnerability CRUD, audit inspection.
   - `SECURITY_ANALYST`: Vulnerability browsing, compliance scans, priority queue evaluation, executive reports.
   - `IT_SUPPORT`: Asset management, software cataloguing, CSV imports, targeted asset scans, operational reports.
   - `AUDITOR`: Read-only access to assets, compliance findings, and executive reports.

3. **User Management & Administration (`epcras.services.user_service`, `epcras.routes.admin`)**:
   - Administrative portal allowing user creation, role assignment, status toggling (enable/disable).
   - Protection against administrator self-disablement to eliminate accidental system lockout.

4. **IT Asset & Inventory Management (`epcras.services.asset_service`, `epcras.routes.asset`)**:
   - Tracks hostnames, IP addresses, OS names and versions, asset types, owners, and organizational departments.
   - Criticality ratings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) feed directly into risk scoring.
   - Cascading deletion ensures associated installed software and compliance records are cleaned up upon asset removal.

5. **Software Catalogue & Inventory Ingestion (`epcras.services.software_service`, `epcras.routes.software`)**:
   - Centralized catalogue preventing duplicate software definitions.
   - Asset-to-software linkage records installed software versions.
   - High-throughput CSV importer with UTF-8 BOM detection, case-insensitive headers, and row-level error reporting.

6. **Vulnerability Management (`epcras.services.vulnerability_service`, `epcras.routes.vulnerability`)**:
   - Manages CVE records, CVSS scores (0.0 to 10.0), severity choices, affected version ranges, fixed versions, and public exploit flags.
   - Bulk vulnerability ingestion supporting CSV files with multiple date formats (`YYYY-MM-DD`, `MM/DD/YYYY`, `DD-MM-YYYY`).

7. **Patch Compliance Engine (`epcras.services.compliance_service`, `epcras.utils.version`)**:
   - Semantic comparison using `packaging.version.Version` to eliminate lexicographical comparison errors.
   - Support for relational operators (`<`, `<=`, `>`, `>=`, `=`), textual and hyphenated ranges (`to`, `-`), discrete lists (`5.6.0, 5.6.1`), explicit OR clauses (`or`, `|`), and OpenSSL letter versions (`1.1.1a`–`1.1.1z`).
   - Assigns `COMPLIANT`, `NON_COMPLIANT`, or `UNKNOWN` to every asset installation.

8. **Patch Priority Engine (`epcras.services.priority_service`)**:
   - Deterministic 0–100 composite scoring formula:
     $$\text{Score} = 100 \times (0.35 \times N_{\text{cvss}} + 0.25 \times N_{\text{crit}} + 0.15 \times N_{\text{exploit}} + 0.10 \times N_{\text{assets}} + 0.10 \times N_{\text{age}} + 0.05 \times N_{\text{patch}})$$
   - Classifies remediations into `CRITICAL` ($\ge 70$), `HIGH` ($50–69$), `MEDIUM` ($30–49$), and `LOW` ($< 30$).

9. **Dashboard & Reporting Service (`epcras.services.dashboard_service`, `epcras.services.report_service`)**:
   - Calculates real-time database metrics: total assets, compliant assets, non-compliant assets, compliance percentage, and critical CVEs.
   - Generates CSV exports and ReportLab styled PDF documents for 5 standard reports:
     - Overall Compliance Report
     - Asset-Wise Compliance Inventory Report
     - Department-Wise Compliance Report
     - Critical & High Vulnerability Risk Report
     - Patch Priority Queue Report

10. **Search, Notifications & Audit (`epcras.services.search_service`, `notification_service`, `audit_service`)**:
    - Centralized multi-parameter search across assets, CVEs, and compliance records.
    - Automated in-app notifications generated when critical vulnerabilities match assets.
    - Immutable audit log tracking all state mutations with user, IP, action category, and success status.

---

## 3. Database Schema & Data Models

EPCRAS utilizes SQLAlchemy ORM with foreign key constraints, cascade rules, and database indexes:

| Table Name | Description | Key Columns & Indexes |
| :--- | :--- | :--- |
| `users` | User accounts and credentials | `id` (PK), `username` (UQ, IDX), `email` (UQ, IDX), `password_hash`, `role`, `is_active` |
| `login_history` | Historical authentication log | `id` (PK), `user_id` (FK -> users.id), `ip_address`, `user_agent`, `status`, `timestamp` |
| `departments` | Organizational groupings | `id` (PK), `name` (UQ, IDX), `description` |
| `assets` | Physical and virtual IT assets | `id` (PK), `hostname` (UQ, IDX), `ip_address` (IDX), `department_id` (FK), `criticality` (IDX) |
| `software` | Master software catalogue | `id` (PK), `name` (IDX), `vendor`, `category` (Composite UQ on name + vendor) |
| `installed_software` | Asset software installations | `id` (PK), `asset_id` (FK -> assets.id), `software_id` (FK -> software.id), `version`, `compliance_status` |
| `vulnerabilities` | CVE advisories & definitions | `id` (PK), `cve_id` (UQ, IDX), `software` (IDX), `cvss_score`, `severity` (IDX), `affected_versions`, `fixed_version` |
| `compliance_results` | Compliance scan findings | `id` (PK), `asset_id` (FK), `installed_software_id` (FK), `status` (IDX), `cve_id` (IDX), `scanned_at` |
| `notifications` | In-app user notifications | `id` (PK), `user_id` (FK -> users.id, nullable), `title`, `message`, `is_read` (IDX), `condition_key` (IDX) |
| `audit_logs` | Immutable system audit records | `id` (PK), `user_id` (FK, nullable), `username` (IDX), `action_category` (IDX), `timestamp` (IDX) |

### Database Engine Compatibility
- **SQLite (Default)**: Located at `instance/epcras.db`. Requires zero configuration, zero daemon overhead, and provides instant evaluation capability.
- **PostgreSQL**: Supported out of the box by updating `DATABASE_URL` in `.env` (e.g., `DATABASE_URL=postgresql://epcras:pass@localhost:5432/epcras_prod`).

---

## 4. Default Setup & Provisioning Procedure

Follow this checklist when onboarding a fresh installation:

```bash
# 1. Clone repository and create virtual environment
cd /opt/epcras/app
python3 -m venv /opt/epcras/venv
source /opt/epcras/venv/bin/activate

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# 3. Configure environment variables
cp .env.example .env
chmod 600 .env
# Edit .env to set a unique SECRET_KEY (generate via python3 -c "import secrets; print(secrets.token_hex(32))")

# 4. Initialize Database Schema
export FLASK_APP=wsgi.py
flask init-db

# 5. Provision Administrator Account
flask seed-admin --username admin --email admin@company.local --password "ProductionAdminPassword123!"

# 6. (Optional) Seed Baseline Vulnerability Records
flask seed-vulnerabilities

# 7. Start application via Gunicorn WSGI
gunicorn --bind 127.0.0.1:8000 --workers 2 wsgi:app
```

---

## 5. Ongoing Maintenance Guidance

### 5.1 SQLite Database Backups
Because SQLite uses a single file, backups can be performed atomically using the `sqlite3` CLI without interrupting service:
```bash
sqlite3 /opt/epcras/app/instance/epcras.db ".backup '/opt/epcras/backups/epcras_backup_$(date +%Y%m%d_%H%M%S).db'"
```
Set up a daily cron job to retain 30 days of compressed backups (see [docs/deployment.md](deployment.md)).

### 5.2 Log Management
Application logs are written to `instance/logs/epcras.log` with automatic 10 MB rotating file handlers (5 backups).
When running under `systemd`, access Gunicorn request logs via:
```bash
sudo journalctl -u epcras -f
```

### 5.3 Upgrading Dependencies & Security Patches
```bash
source /opt/epcras/venv/bin/activate
pip list --outdated
pip install --upgrade -r requirements.txt
pytest -v
sudo systemctl restart epcras
```

---

## 6. Known Limitations

In the interest of full engineering transparency, the following technical limitations are documented:

1. **Passive Inventory Ingestion**:
   - Assets and installed software must be registered via web forms or CSV imports. EPCRAS does not include an active network scanner (e.g. Nmap) or endpoint agent daemon.
2. **Proprietary Version Formats**:
   - While PEP 440, SemVer, OpenSSL, and relational range expressions are supported, non-standard proprietary version formats (e.g., date-based builds with arbitrary suffixes like `build-2023.11.beta-v3`) that cannot be parsed by `packaging.version` default safely to `UNKNOWN` compliance status.
3. **SQLite Write Concurrency**:
   - SQLite enforces database-level write locking. For small to mid-sized organizations (up to 50 concurrent administrators and 10,000 assets), SQLite performs excellently. If scaling to large enterprise deployments with continuous multi-tenant automated writes, migrate to PostgreSQL via `DATABASE_URL`.
4. **Synchronous Compliance Runs**:
   - Running an organization-wide compliance scan on 10,000+ software items executes within a single synchronous request (typically ~1–2 seconds on modern hardware). For massive asset counts (50,000+), an asynchronous task worker (e.g. RQ or Celery) would be recommended.

---

## 7. Future Enhancements Roadmap

1. **National Vulnerability Database (NVD) 2.0 API Ingestion**:
   - Automated nightly synchronization with NIST NVD API and CISA KEV (Known Exploited Vulnerabilities) feed to update CVE definitions automatically.
2. **Endpoint Discovery Agents**:
   - Lightweight cross-platform Python or Go agent to automatically inventory installed packages (`dpkg`, `rpm`, `pacman`, Windows registry) and post telemetry to EPCRAS REST APIs.
3. **Single Sign-On (SSO / OIDC)**:
   - SAML 2.0 and OAuth2/OIDC integration allowing enterprise authentication through Microsoft Entra ID (Azure AD), Okta, Keycloak, or Google Workspace.
4. **Automated Remediation Webhooks**:
   - Event-driven webhook notifications dispatched to orchestration platforms (Ansible, Puppet, SaltStack) when high-scoring patches enter the queue.
5. **Multi-Tenancy & Segmented Access**:
   - Department-level scoped administration allowing IT Support users to view and manage only assets belonging to their respective organizational unit.

---

## 8. Verification & Sign-Off

The final test suite run confirms all 156 unit, integration, security, and system-level acceptance tests pass:

```
============================= 156 passed in 30.63s =============================
```

EPCRAS is verified ready for operational handover and production deployment.
