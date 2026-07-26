# Software Requirements Specification (SRS)
## Enterprise Patch Compliance and Risk Assessment System (EPCRAS)

---

### 1. Introduction

#### 1.1 Background
In modern organizational IT environments, software patch management is a cornerstone of cybersecurity hygiene. Unpatched software vulnerabilities remain one of the primary vectors exploited by threat actors. However, tracking patch levels, assessing security risks, and prioritizing remediation efforts across hundreds of heterogeneous assets and software installations poses significant operational challenges. 

The Enterprise Patch Compliance and Risk Assessment System (EPCRAS) is designed to solve this problem by providing a central, lightweight platform to monitor asset inventories, track software installations, correlate software versions against Known Vulnerabilities and Exposures (CVEs), compute patch compliance statuses, and score remediation priorities based on asset criticality and vulnerability severity.

#### 1.2 Document Overview
This Software Requirements Specification (SRS) defines the complete functional and non-functional requirements, architectural constraints, logical data structures, user characteristics, and requirement traceability matrix for EPCRAS.

---

### 2. Purpose

The purpose of this SRS document is to establish a clear, comprehensive baseline for the design, implementation, testing, and evaluation of EPCRAS. It serves as the single source of truth for developer design decisions, system verification plans, and project scope management throughout its 3-month development lifecycle.

---

### 3. Scope

#### 3.1 In-Scope Capabilities
EPCRAS provides a web-based management interface for security analysts, asset managers, and system administrators. The system encompasses:
- User Authentication and Server-Side Role-Based Access Control (RBAC).
- IT Asset Inventory tracking (hardware metadata, environment, criticality level).
- Installed Software Inventory tracking per asset.
- CVE / Vulnerability database management (CVSS scores, severity, affected versions, remediation details).
- Patch Compliance Analysis Engine (correlating software versions against known vulnerabilities).
- Patch Priority Engine (scoring patch urgency using vulnerability severity and asset business criticality).
- Executive and Operational Dashboard (visual metrics, charts, compliance status overview).
- Compliance and Risk Assessment Report Generation (PDF exports using ReportLab and CSV downloads).
- Multi-criteria Search and Filtering across assets, software, and vulnerabilities.
- System Notifications & In-App Alerts for critical non-compliance events.
- Administrative Management and Immutable Audit Logging.

#### 3.2 Out-of-Scope Explicit Boundaries
To ensure realistic completion within a 3-month individual academic timeline on a low-resource Linux laptop, the following items are strictly **out of scope**:
- Remote endpoint agents or daemon processes.
- Automatic or remote patch deployment / script execution.
- Microservices, container orchestration (Docker/Kubernetes requirements), or cloud infrastructure.
- Machine Learning / AI algorithms for predictive risk analysis.
- Live automated NVD API synchronization (data ingestion is handled via structured manual entry or offline CSV import).

---

### 4. Definitions and Abbreviations

| Term / Abbreviation | Definition |
| :--- | :--- |
| **EPCRAS** | Enterprise Patch Compliance and Risk Assessment System |
| **CVE** | Common Vulnerabilities and Exposures (dictionary of publicly disclosed cybersecurity vulnerabilities) |
| **CVSS** | Common Vulnerability Scoring System (standard numerical score from 0.0 to 10.0 representing vulnerability severity) |
| **RBAC** | Role-Based Access Control |
| **SRS** | Software Requirements Specification |
| **RTM** | Requirement Traceability Matrix |
| **ORM** | Object-Relational Mapping (Flask-SQLAlchemy abstraction layer) |
| **WTF** | Web Tool Kit Form (Flask-WTF for form handling and CSRF validation) |
| **Asset Criticality** | A weight assigned to an IT asset indicating its business importance (e.g., Low, Medium, High, Critical) |

---

### 5. Product Perspective

EPCRAS is configured as a self-contained, monolithic web application. It follows a classical Model-View-Controller / Model-View-Template pattern implemented via Python Flask and Flask Blueprints.

```
                    +----------------------------------------+
                    |           Web Browser (Client)         |
                    | Bootstrap 5 / Vanilla JS / Chart.js    |
                    +-------------------+--------------------+
                                        |
                                   HTTP / HTML
                                        |
                    +-------------------v--------------------+
                    |       Flask Web Application            |
                    |  (Blueprints / Security / Routing)     |
                    +-------------------+--------------------+
                                        |
                               Separated Logic
                                        |
                    +-------------------v--------------------+
                    |     Business Logic & Engines           |
                    | (Compliance Engine, Priority Engine,   |
                    |      Report Services, Audit Log)       |
                    +-------------------+--------------------+
                                        |
                                 SQLAlchemy ORM
                                        |
                    +-------------------v--------------------+
                    |          SQLite Database               |
                    +----------------------------------------+
```

---

### 6. Product Functions

1. **User Authentication & RBAC**: Secure login, session management, and role-based authorization for administrative and analytical workflows.
2. **Asset Inventory Management**: Registration, updating, and categorization of organizational IT assets.
3. **Software Inventory Management**: Tracking software applications and version numbers installed on assets.
4. **Vulnerability Management**: Cataloging CVEs, severity ratings, affected software specifications, and patch recommendations.
5. **Patch Compliance Engine**: Automated correlation of software inventories against vulnerability records to flag outdated/vulnerable software.
6. **Patch Priority Engine**: Algorithmic scoring that calculates urgency based on CVSS scores, asset criticality, exposure, and patch availability.
7. **Dashboard Visualization**: Visual representation of overall security posture, top vulnerable assets, and compliance trends via Chart.js.
8. **Reporting Engine**: Generating detailed audit reports in PDF (ReportLab) and CSV formats.
9. **Search & Filter**: Fast querying across all inventory, CVE, and compliance data.
10. **Notifications System**: In-app alert highlights for critical compliance breaches.
11. **System Administration & Audit**: Managing user accounts, role permissions, and viewing append-only audit trail logs.

---

### 7. User Characteristics

| User Role | Technical Expertise | System Responsibilities | Access Level |
| :--- | :--- | :--- | :--- |
| **System Administrator** | High | System configuration, user account management, role assignment, audit log inspection. | Full administrative access |
| **Security Analyst** | High / Medium | Vulnerability database maintenance, priority scoring configuration, compliance evaluation, report generation. | Read/Write on Assets, Software, CVEs, Reports |
| **IT Asset Manager** | Medium | Asset inventory registration, software cataloging, hardware/software association. | Read/Write on Assets & Software; Read-only on CVEs/Reports |
| **Auditor / Read-Only** | Low / Medium | Viewing dashboard summaries, reviewing compliance reports, inspecting compliance status. | Read-only across all non-administrative modules |

---

### 8. Constraints

1. **Hardware Constraints**: Must execute efficiently on low-resource Linux hardware (e.g., dual-core CPU, 4 GB RAM).
2. **Timeline Constraints**: Individual academic project to be designed, developed, tested, and documented within 3 months.
3. **Architectural Constraints**: Monolithic architecture; modular code separation using Flask Blueprints; business logic decoupled from routes.
4. **Technology Stack**:
   - Backend: Python 3, Flask, Flask-SQLAlchemy, Flask-Login, Flask-WTF.
   - Database: SQLite 3.
   - Frontend: Jinja2 HTML templates, Bootstrap 5 CSS, Vanilla JavaScript, Chart.js.
   - PDF Engine: ReportLab.
   - Testing: pytest.
5. **Security Constraints**: Password hashing using secure algorithms; strict server-side authorization enforcement; CSRF token validation.

---

### 9. Assumptions

1. The application operates primarily within an internal local network or single-machine environment.
2. System administrators will maintain up-to-date accurate software and asset inventories either via manual entry or bulk CSV imports.
3. CVE data input contains standard CVSS v3 vectors and scores.
4. The SQLite database will handle expected academic/small-enterprise workloads (up to 10,000 asset/software entries) without requiring client-server RDBMS setup.

---

### 10. Functional Requirements (FR1–FR11)

#### FR1: User Authentication & Access Control
- **FR1.1**: The system shall allow registered users to log in securely using username/email and password.
- **FR1.2**: The system shall hash all stored passwords using secure password hashing algorithms (e.g., Werkzeug `generate_password_hash`).
- **FR1.3**: The system shall manage user sessions securely (Flask-Login) and enforce session expiration upon logout or inactivity.
- **FR1.4**: The system shall enforce server-side Role-Based Access Control (RBAC) across four roles: Administrator, Security Analyst, Asset Manager, and Auditor.
- **FR1.5**: The system shall deny unauthorized access to restricted endpoints and redirect unauthenticated users to the login page.

#### FR2: Asset Management
- **FR2.1**: The system shall allow authorized users (Admin, Asset Manager) to create, view, update, and delete IT assets.
- **FR2.2**: Asset attributes shall include: Unique Asset ID, Hostname, IP Address, MAC Address, Operating System, Environment (Production, Staging, Development), Criticality Level (Low, Medium, High, Critical), Location, and Status (Active, Decommissioned, Maintenance).
- **FR2.3**: The system shall prevent duplicate asset hostnames or IP addresses.
- **FR2.4**: The system shall allow soft deletion or status updating of assets to preserve historical compliance logs.

#### FR3: Software Inventory
- **FR3.1**: The system shall maintain a catalog of software products (Vendor, Software Name, Category).
- **FR3.2**: The system shall record software installations linked to specific assets, including exact Installed Version, Installation Date, and License/Patch state.
- **FR3.3**: The system shall support bulk CSV importing for asset software inventory mappings.
- **FR3.4**: The system shall allow authorized users to edit or disassociate software installations from assets.

#### FR4: Vulnerability Database
- **FR4.1**: The system shall maintain a catalog of CVE vulnerability records.
- **FR4.2**: CVE attributes shall include: CVE ID (e.g., CVE-2024-1234), Description, CVSS v3 Score (0.0 to 10.0), Severity Rating (Low, Medium, High, Critical), Affected Vendor/Product, Affected Version Range, Remediation/Patch Details, and Release Date.
- **FR4.3**: The system shall allow authorized users (Admin, Security Analyst) to add, modify, search, and delete CVE records.
- **FR4.4**: The system shall support importing CVE data via structured CSV templates.

#### FR5: Patch Compliance Analysis Engine
- **FR5.1**: The system shall feature an automated matching engine that compares asset software versions against cataloged CVE records.
- **FR5.2**: The engine shall evaluate compliance statuses for each asset software association:
  - `Compliant`: Software is on the latest recommended version with no matching unpatched CVEs.
  - `Non-Compliant (Vulnerable)`: Software version falls within an affected CVE range and a patch is available.
  - `Unpatched Risk`: Software version is affected by a CVE but no patch is currently available.
- **FR5.3**: The system shall compute overall compliance percentages at both individual asset and organizational fleet levels.
- **FR5.4**: The engine shall trigger compliance re-calculation upon creation/update of assets, software associations, or CVE records.

#### FR6: Dashboard
- **FR6.1**: The system shall display an interactive visual dashboard summarizing key metrics.
- **FR6.2**: Visual cards shall present: Total Assets, Total Installed Software, Total Known Vulnerabilities, Overall Compliance Rate (%), and High/Critical Risk Counts.
- **FR6.3**: Visual charts (Chart.js) shall display:
  - Compliance rate distribution pie/donut chart.
  - Vulnerability distribution by severity (Bar chart).
  - Top 5 most vulnerable assets.
- **FR6.4**: Dashboard content shall be scoped dynamically based on the logged-in user's role permissions.

#### FR7: Report Generation
- **FR7.1**: The system shall generate comprehensive security audit and compliance reports.
- **FR7.2**: The system shall support export of reports in PDF format utilizing ReportLab.
- **FR7.3**: The system shall support export of compliance data in CSV format for spreadsheet analysis.
- **FR7.4**: PDF reports shall include summary tables, executive metrics, detailed non-compliant asset listings, and remediation recommendations.
- **FR7.5**: The system shall allow users to filter report scope by Asset Environment, Criticality, or Vulnerability Severity prior to export.

#### FR8: Search and Filtering
- **FR8.1**: The system shall provide a unified search interface to query across assets, installed software, and CVE databases.
- **FR8.2**: Filters shall include: Keyword search, Asset Criticality, Asset Status, Software Vendor, CVE Severity Rating, and Compliance Status.
- **FR8.3**: Search results shall display paginated data tables with sorting controls.

#### FR9: Notifications System
- **FR9.1**: The system shall generate in-app alert notifications for critical security events.
- **FR9.2**: Notification triggers shall include:
  - Discovery of Critical (CVSS >= 9.0) vulnerabilities affecting active assets.
  - Non-compliance on high-criticality assets.
  - Administrative role changes or security configuration edits.
- **FR9.3**: Users shall be able to view, mark as read, and clear notifications from an in-app notification center.

#### FR10: Administration & Audit Logs
- **FR10.1**: System Administrators shall have access to an administration panel for user account management (creating users, resetting passwords, updating roles).
- **FR10.2**: The system shall maintain an append-only Audit Log recording security-relevant actions.
- **FR10.3**: Audit Log entries shall record: Timestamp, Actor User ID/Username, Action Category (Auth, Asset Edit, CVE Update, Role Change), Target Entity, IP Address, and Event Outcome (Success/Failure).
- **FR10.4**: Audit logs shall be read-only and immutable to all users, including Administrators.

#### FR11: Patch Priority Engine
- **FR11.1**: The system shall implement an algorithmic Patch Priority Scoring Engine.
- **FR11.2**: The engine shall calculate a Patch Priority Score (PPS) ranging from 0.0 to 100.0 for each unpatched vulnerability instance.
- **FR11.3**: The score calculation formula shall incorporate:
  - Vulnerability CVSS v3 Base Score (weight: ~40%).
  - Asset Business Criticality Weight (Critical=1.0, High=0.8, Medium=0.5, Low=0.2) (weight: ~35%).
  - Asset Exposure / Environment Weight (Production=1.0, Staging=0.7, Development=0.4) (weight: ~15%).
  - Patch Availability Status (Patch Available=1.0, Workaround Only=0.6) (weight: ~10%).
- **FR11.4**: The system shall rank unpatched vulnerabilities by priority score to provide actionable remediation guidance for analysts.

---

### 11. External Interface Requirements

#### 11.1 User Interfaces
- Web browser interface compatible with modern standards-compliant browsers (Firefox, Chrome, Edge).
- Styled using Bootstrap 5, providing clean typography, responsive layout grids, dark/light visual contrast, and interactive form controls.
- Dynamic visualizations driven by Chart.js.

#### 11.2 Software Interfaces
- Python 3 runtime environment.
- SQLite database connection managed via Flask-SQLAlchemy ORM.
- ReportLab library interface for programmatic PDF generation.
- Flask-WTF interface for server-side form rendering and CSRF protection.

#### 11.3 Hardware Interfaces
- Standard network interface (TCP/IP stack for HTTP communication on configurable localhost ports).

---

### 12. Non-Functional Requirements

#### 12.1 Performance Requirements
- **Page Load Time**: Web interface pages shall render in under 2 seconds under standard load.
- **Report Generation**: PDF/CSV export generation shall complete within 3 seconds for datasets up to 5,000 records.
- **Low-Resource Footprint**: Application memory consumption shall remain below 250 MB RAM during normal operation.

#### 12.2 Security Requirements
- **Server-Side Security**: All authorization, validation, and risk computations must be strictly enforced server-side.
- **Password Security**: Passwords stored using PBKDF2/scrypt cryptographic hashing.
- **Injection Prevention**: Database interactions handled exclusively via SQLAlchemy ORM parameterized queries to eliminate SQL injection risks.
- **CSRF Protection**: All POST/PUT/DELETE forms protected by Flask-WTF CSRF tokens.
- **XSS Prevention**: Output encoding handled automatically via Jinja2 HTML escaping.

#### 12.3 Usability Requirements
- User interface must be intuitive, requiring minimal user training for security analysts.
- Navigation header must provide clear links to key functional modules (Dashboard, Assets, Software, Vulnerabilities, Compliance, Reports, Admin).

#### 12.4 Reliability and Maintainability Requirements
- **ACID Compliance**: Transaction management backed by SQLite transactional guarantees.
- **Modular Codebase**: Strict separation of concerns using Flask Blueprints, routing layers, and independent business logic service modules.
- **Test Coverage**: Critical business logic (Compliance Engine, Priority Engine, Authentication, RBAC) must be covered by automated tests using pytest.

---

### 13. Logical Database Requirements

The logical data model consists of the following primary entities and relationships:

```
  +------------------+         1:N         +---------------------+
  |      User        |-------------------->|      AuditLog       |
  +------------------+                     +---------------------+
  | id (PK)          |
  | username         |         1:N         +---------------------+
  | email            |-------------------->|    Notification     |
  | password_hash    |                     +---------------------+
  | role             |
  +------------------+

  +------------------+         1:N         +---------------------+
  |      Asset       |-------------------->|    AssetSoftware    |
  +------------------+                     +---------------------+
  | id (PK)          |                     | id (PK)             |
  | hostname         |                     | asset_id (FK)       |
  | ip_address       |                     | software_id (FK)    |
  | mac_address      |                     | installed_version   |
  | os               |                     | installation_date   |
  | environment      |                     +---------------------+
  | criticality      |                                |
  | status           |                                | N:1
  +------------------+                                v
                                           +---------------------+
                                           |      Software       |
                                           +---------------------+
                                           | id (PK)             |
                                           | vendor              |
                                           | name                |
                                           | category            |
                                           +---------------------+
                                                      |
                                                      | 1:N
                                                      v
  +------------------+         1:N         +---------------------+
  |  Vulnerability   |-------------------->| VulnerableSoftware  |
  +------------------+                     +---------------------+
  | id (PK)          |                     | id (PK)             |
  | cve_id           |                     | vulnerability_id(FK)|
  | description      |                     | software_id (FK)    |
  | cvss_score       |                     | affected_version_min|
  | severity         |                     | affected_version_max|
  | patch_available  |                     | fixed_version       |
  +------------------+                     +---------------------+
```

---

### 14. Design Constraints

1. **Monolithic Architecture**: Designed as a clean single-process Flask application without microservices complexity.
2. **Local Persistence**: Database restricted to SQLite to avoid heavy external database server overhead.
3. **No External Runtime API Dependencies**: Network-isolated capability ensuring core compliance computations operate without external web service connectivity.
4. **Python Standards**: Compliance with PEP 8 coding standards and type annotations across core logic modules.

---

### 15. Requirement Traceability Matrix (RTM)

| Requirement ID | Description | Primary Route / Blueprint | Core Logic / Service Module | Database Entities | Test Module |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FR1** | User Authentication & RBAC | `auth_bp` | `auth_service.py` | `User` | `test_auth.py` |
| **FR2** | Asset Management | `asset_bp` | `asset_service.py` | `Asset` | `test_asset.py` |
| **FR3** | Software Inventory | `software_bp` | `software_service.py` | `Software`, `AssetSoftware` | `test_software.py` |
| **FR4** | Vulnerability Database | `vulnerability_bp`| `vulnerability_service.py` | `Vulnerability`, `VulnerableSoftware` | `test_vulnerability.py` |
| **FR5** | Patch Compliance Analysis | `compliance_bp` | `compliance_engine.py` | `Asset`, `Software`, `Vulnerability` | `test_compliance.py` |
| **FR6** | Dashboard | `dashboard_bp` | `dashboard_service.py` | All Entities | `test_dashboard.py` |
| **FR7** | Report Generation | `report_bp` | `report_service.py` | All Entities | `test_report.py` |
| **FR8** | Search and Filtering | `search_bp` | `search_service.py` | All Entities | `test_search.py` |
| **FR9** | Notifications System | `notification_bp` | `notification_service.py` | `Notification` | `test_notification.py` |
| **FR10** | Administration & Audit Logs | `admin_bp` | `admin_service.py`, `audit_service.py` | `User`, `AuditLog` | `test_admin.py` |
| **FR11** | Patch Priority Engine | `compliance_bp` | `priority_engine.py` | `Asset`, `Vulnerability` | `test_priority.py` |

---

### 16. Future Enhancements

The following enhancements represent potential post-academic roadmap items:
1. Automated National Vulnerability Database (NVD) REST API synchronization connector.
2. Cross-platform light endpoint discovery script (read-only system information collector).
3. Integration with IT Service Management (ITSM) ticketing systems (e.g., Jira/Redmine API hooks).
4. Multi-factor authentication (MFA) via Time-based One-Time Password (TOTP).
