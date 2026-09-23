# EPCRAS — Enterprise Patch Compliance and Risk Assessment System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.x-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-Academic%20%2F%20Educational-lightgrey.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-156%20passed%20(100%25)-brightgreen.svg)]()

EPCRAS (**Enterprise Patch Compliance and Risk Assessment System**) is a comprehensive web-based cybersecurity platform designed to automate patch compliance auditing, vulnerability exposure analysis, and risk-based remediation prioritization across enterprise IT infrastructure.

Built with Python, Flask, SQLAlchemy, and Bootstrap 5, EPCRAS operates as a lightweight, auditable, and self-contained system ideal for low-resource Linux servers, academic testbeds, and internal enterprise environments without requiring complex container orchestrators or cloud microservices.

---

## 1. Key Features

- **IT Asset & Inventory Management**:
  - Full CRUD operations for IT assets (Servers, Workstations, Network Devices, Virtual Machines).
  - Departmental organization and asset criticality tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Software catalogue management with version tracking and CSV bulk import with UTF-8 BOM support.
- **Vulnerability Tracking & CVE Database**:
  - Curated vulnerability repository tracking CVE IDs, CVSS v3.1 scores, severities, affected version ranges, fixed versions, and public exploit flags.
  - Bulk CVE ingestion via structured CSV.
- **Automated Patch Compliance Engine**:
  - PEP 440 semantic version comparison engine with support for relational operators (`<`, `<=`, `>`, `>=`, `=`), bounded ranges (`to`, `-`), discrete version lists, and OpenSSL trailing letter patch schemes (`1.1.1a`–`1.1.1z`).
  - Automated correlation determining `COMPLIANT`, `NON_COMPLIANT`, or `UNKNOWN` statuses across all installed software.
- **Deterministic 0–100 Patch Priority Engine**:
  - Multi-factor risk scoring model prioritizing remediation by evaluating CVSS (35%), asset criticality (25%), exploit availability (15%), blast radius (10%), exposure age (10%), and patch readiness (5%).
  - Categorization into transparent priority tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) with human-readable factor explanations.
- **Executive Security Dashboard & Reporting**:
  - Real-time compliance gauges, posture donuts, and department-wise compliance bar charts.
  - Multi-format report export (CSV and styled PDF via ReportLab) across 5 report types.
- **Role-Based Access Control (RBAC) & Governance**:
  - Four distinct roles: `ADMINISTRATOR`, `SECURITY_ANALYST`, `IT_SUPPORT`, and `AUDITOR`.
  - Comprehensive, immutable audit trail logging all system events with remote IP and timestamp tracking.
- **In-App Real-Time Alerts**:
  - Targeted notification feed triggered upon critical CVE matching or non-compliant asset discovery with read-state tracking.

---

## 2. Screenshots (Placeholders)

| Executive Security Dashboard | Patch Priority Queue & Remediation |
| :---: | :---: |
| ![Executive Dashboard Placeholder](docs/screenshots/dashboard_placeholder.png)<br>_Real-time compliance rates, metric cards, and charts_ | ![Patch Priority Queue Placeholder](docs/screenshots/priority_placeholder.png)<br>_Ranked 0–100 scores with factor breakdowns_ |

| Non-Compliant Findings & Vulnerability Matrix | Report Center (PDF & CSV Exports) |
| :---: | :---: |
| ![Vulnerability Matrix Placeholder](docs/screenshots/vuln_placeholder.png)<br>_Granular asset-to-CVE correlation & affected versions_ | ![Report Center Placeholder](docs/screenshots/reports_placeholder.png)<br>_Exportable compliance, audit, and inventory reports_ |

---

## 3. Architecture Summary

EPCRAS follows a modular monolithic architecture with clean service-layer separation:

```
+-------------------------------------------------------------------------+
|                           Client Web Browser                            |
+-------------------------------------------------------------------------+
                                    |
                                    | HTTPS / HTTP
                                    v
+-------------------------------------------------------------------------+
|                  Nginx Reverse Proxy (Optional / Prod)                  |
|          SSL Termination, Static Asset Serving, Client Buffering        |
+-------------------------------------------------------------------------+
                                    |
                                    | Reverse Proxy
                                    v
+-------------------------------------------------------------------------+
|                       Gunicorn WSGI Server                              |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                        EPCRAS Flask Application                         |
|  +-------------------+  +--------------------+  +--------------------+  |
|  | Presentation      |  | Business Logic     |  | Security & Auth    |  |
|  | Blueprints (Jinja)|  | Services           |  | RBAC, CSRF, Audit  |  |
|  +-------------------+  +--------------------+  +--------------------+  |
|            |                      |                       |             |
|            v                      v                       v             |
|  +-------------------------------------------------------------------+  |
|  |               SQLAlchemy ORM Data Models                          |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                 Relational Database (SQLite / PostgreSQL)                |
|                  Default Academic Engine: instance/epcras.db            |
+-------------------------------------------------------------------------+
```

---

## 4. Installation & Local Setup

### 4.1 Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14
- Standard Linux, macOS, or Windows environment

### 4.2 Clone & Environment Initialization
```bash
# Clone the repository
git clone https://github.com/Hareekshith/EPCRAS.git
cd EPCRAS

# Create isolated Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

---

## 5. Configuration

EPCRAS uses environment variables managed via a `.env` file. Copy the provided template:

```bash
cp .env.example .env
```

Key environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `FLASK_CONFIG` | Application mode (`development`, `testing`, `production`) | `development` |
| `SECRET_KEY` | Session and CSRF encryption key | High-entropy key |
| `DATABASE_URL` | Database connection URI | `sqlite:///instance/epcras.db` |
| `SESSION_COOKIE_SECURE` | Set `true` if serving over HTTPS | `false` |
| `LOG_LEVEL` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO` |
| `USE_PROXY_FIX` | Enables ProxyFix for Nginx / reverse proxy headers | `false` (dev) / `true` (prod) |

---

## 6. Running Locally

### 6.1 Database Setup & Seeding
```bash
# Ensure virtual environment is active
source .venv/bin/activate
export FLASK_APP=wsgi.py

# 1. Initialize SQLite Database Schema
flask init-db

# 2. Provision an Administrator Account
flask seed-admin --username admin --email admin@example.local --password "AdminSecret123!"

# 3. (Optional) Load Curated Baseline Vulnerabilities (Log4j, XZ, libwebp, Spring4Shell)
flask seed-vulnerabilities
```

### 6.2 Running the Development Server
```bash
python run.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

### 6.3 Running with Production Gunicorn WSGI
```bash
gunicorn --bind 127.0.0.1:8000 --workers 2 wsgi:app
```
Navigate to: **`http://127.0.0.1:8000`**

---

## 7. Running Tests

The test suite includes 156 unit, integration, RBAC matrix, malicious input, and system-level acceptance tests:

```bash
# Run the complete test suite
pytest -v

# Run with coverage report
pytest --cov=src/epcras --cov-report=term-missing
```

---

## 8. Project Structure

```
EPCRAS/
├── .env.example                 # Production environment variables template
├── .gitignore                   # Git exclusion rules (ignores .env and SQLite DBs)
├── README.md                    # Project documentation
├── requirements.txt             # Production and test Python dependencies
├── run.py                       # Local development startup script
├── setup.py                     # Python package installer
├── wsgi.py                      # Production WSGI entrypoint for Gunicorn
├── docs/                        # Formal architectural, design, & testing docs
│   ├── SRS.md                   # Software Requirements Specification
│   ├── design.md                # System Architecture & Design Specification
│   ├── compliance-engine.md     # Compliance engine version comparison specification
│   ├── priority-engine.md       # Priority scoring model & mathematical specification
│   ├── testing.md               # Test strategy, categories, defects, and verification
│   ├── UAT.md                   # Human User Acceptance Testing checklist
│   ├── deployment.md            # Linux / Gunicorn / Nginx deployment guide
│   └── handover.md              # Project handover, maintenance, & architecture summary
├── src/epcras/                  # Application source package
│   ├── __init__.py              # Application factory (create_app), logging, ProxyFix
│   ├── config.py                # Configuration classes (Dev, Test, Prod)
│   ├── extensions.py            # Flask-SQLAlchemy, Flask-Login, Flask-WTF
│   ├── cli.py                   # CLI commands (init-db, seed-admin, seed-vulnerabilities)
│   ├── forms/                   # WTForms validation classes
│   ├── models/                  # SQLAlchemy ORM models (User, Asset, Software, Vuln, etc.)
│   ├── routes/                  # Controller blueprints (auth, admin, asset, compliance, etc.)
│   ├── services/                # Business logic layer (scoring, compliance, reports, audit)
│   ├── static/                  # CSS stylesheets and client assets
│   ├── templates/               # Jinja2 HTML templates
│   └── utils/                   # Non-lexicographical version parsing engine
└── tests/                       # Automated test suite (156 tests)
    ├── conftest.py              # Pytest fixtures and mock environments
    ├── unit/                    # Unit tests for utils, models, services
    └── integration/             # Integration, RBAC matrix, malicious input, system UAT
```

---

## 9. Algorithmic Specifications

### 9.1 Patch Compliance Analysis Algorithm
The compliance engine correlates installed software against known vulnerabilities using PEP 440 semantic parsing rather than lexicographical string comparison.

For each installed software instance linked to an asset:
1. **Normalization**: Strips `v`/`V` prefixes and handles vendor quirks (e.g. OpenSSL letter patches `1.1.1f` mapped to numeric equivalents).
2. **Fixed Version Check**: If $\text{installed\_version} \ge \text{fixed\_version}$, software is marked **`COMPLIANT`**.
3. **Range Check**: If version falls within advisory ranges (e.g. `< 1.3.2`, `5.6.0, 5.6.1`, or `5.3.0 to 5.3.17`), software is marked **`NON_COMPLIANT`**.
4. **Unknown Fallback**: If version cannot be parsed or no vulnerability definitions exist, status defaults safely to **`UNKNOWN`**.

### 9.2 Patch Priority Scoring Model
EPCRAS uses a transparent, explainable 0–100 mathematical scoring model across six weighted factors:

$$\text{Priority Score} = 100 \times \sum_{i=1}^6 \left(W_i \times N_i\right)$$

| Factor ($F_i$) | Weight ($W_i$) | Normalization Formula ($N_i$) |
| :--- | :---: | :--- |
| **CVSS v3.1** | **35%** | $N_{\text{cvss}} = \frac{\text{CVSS}}{10.0}$ |
| **Asset Criticality** | **25%** | $\text{CRITICAL}=1.0, \text{HIGH}=0.75, \text{MEDIUM}=0.50, \text{LOW}=0.25$ |
| **Exploit Availability** | **15%** | $\text{Public Exploit}=1.0, \text{None}=0.0$ |
| **Affected Asset Count** | **10%** | $N_{\text{assets}} = \min\left(1.0, \frac{A_{\text{affected}}}{A_{\text{total}}}\right)$ |
| **Vulnerability Age** | **10%** | $N_{\text{age}} = \min\left(1.0, \frac{\text{Days Since Disclosure}}{365}\right)$ |
| **Patch Availability** | **5%** | $\text{Patch Available}=1.0, \text{Unpatched}=0.0$ |

#### Priority Tiers
- **`CRITICAL`** ($\ge 70$ points): Immediate remediation required (active exploits / mission-critical systems).
- **`HIGH`** ($50 - 69$ points): High priority remediation within scheduled patch window.
- **`MEDIUM`** ($30 - 49$ points): Moderate exposure; standard maintenance cycle.
- **`LOW`** ($< 30$ points): Minimal exposure; patch as convenient.

---

## 10. Known Limitations & Future Scope

### Current Limitations
1. **Manual / CSV Asset Discovery**: Asset registration is performed via web forms or CSV ingestion; direct active network scanning (e.g., Nmap or WMI/SSH agents) is not included out-of-the-box.
2. **Version Syntax Coverage**: While standard SemVer, PEP 440, OpenSSL, and relational operators are supported, non-standard proprietary version numbering formats may evaluate to `UNKNOWN`.
3. **SQLite Single-Writer Concurrency**: While SQLite is ideal for low-resource environments, organizations with hundreds of concurrent administrators modifying records simultaneously should configure PostgreSQL via `DATABASE_URL`.

### Future Scope
1. **Automated Threat Feeds**: Direct API synchronization with the NIST National Vulnerability Database (NVD) and CISA Known Exploited Vulnerabilities (KEV) catalog.
2. **Agent-Based Discovery**: Lightweight endpoint agents for automated telemetry of installed software packages (APT, RPM, Windows Registry).
3. **Single Sign-On (SSO)**: SAML 2.0 / OpenID Connect (OIDC) integration with Active Directory, Okta, or Keycloak.
4. **Automated Remediation Hooks**: Webhook dispatchers triggering Ansible playbooks or patch management tools upon priority queue approval.

---

## 11. Project Handover & Documentation References

Detailed technical documentation is maintained in the `docs/` folder:
- **[docs/deployment.md](docs/deployment.md)**: Production deployment instructions, Nginx reverse proxy, and systemd service templates.
- **[docs/UAT.md](docs/UAT.md)**: Human User Acceptance Testing checklist across Administrator, Analyst, and IT Support roles.
- **[docs/testing.md](docs/testing.md)**: Testing strategy, category breakdown, defect root causes, and verification metrics.
- **[docs/handover.md](docs/handover.md)**: System overview, maintenance guidance, database schema, and operational lifecycle.
- **[docs/SRS.md](docs/SRS.md)** & **[docs/design.md](docs/design.md)**: Core functional requirements and system architecture.