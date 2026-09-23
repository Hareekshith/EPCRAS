# EPCRAS User Acceptance Testing (UAT) Checklist & Test Plan

**Document Version:** 1.0.0  
**Target System:** Enterprise Patch Compliance and Risk Assessment System (EPCRAS)  
**System Classification:** Enterprise Web Application (Flask / SQLAlchemy / Bootstrap 5)  
**Document Purpose:** Formal User Acceptance Testing (UAT) checklist and execution plan for human validation across all authorized user roles.

---

## 1. Overview & Instructions for Testers

### 1.1 Scope and Objective
This document provides user acceptance test scenarios covering all primary business workflows within EPCRAS. Testers must validate the system from end to end using modern desktop web browsers (Chrome, Edge, Firefox, Safari) against a deployed EPCRAS instance.

### 1.2 Target User Roles
- **Administrator (`ADMINISTRATOR`)**: Complete administrative rights, user provisioning, system configuration, vulnerability management, audit log inspection, and system-wide visibility.
- **Security Analyst (`SECURITY_ANALYST`)**: Vulnerability risk assessment, compliance posture analysis, patch priority queue analysis, executive report generation, and security audit search.
- **IT Support (`IT_SUPPORT`)**: IT asset inventory onboarding, software cataloguing, CSV batch inventory ingestion, asset-level compliance verification, and operational reporting.

### 1.3 Execution Guidelines
1. Execute test scenarios in sequence or by role as designated.
2. Verify all **Preconditions** before executing steps.
3. Follow the numbered **Steps** exactly as written.
4. Compare system behavior against **Expected Result**.
5. **Do not modify test definitions**: Record actual behavior in the **Actual Result Placeholder** and mark the **Pass/Fail Placeholder** based on observed results.

---

## 2. UAT Summary Tracking Matrix

| Scenario ID | User Role | Workflow Description | Status | Tested By | Date |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **UAT-ADM-01** | Administrator | Administrative Authentication & Session Initialization | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ADM-02** | Administrator | User Account Creation & Role Assignment | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ADM-03** | Administrator | User Modification & Status Toggle (Account Disabling) | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ADM-04** | Administrator | Self-Disable Restriction Enforcement | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ADM-05** | Administrator | Manual Vulnerability (CVE) Ingestion & Validation | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ADM-06** | Administrator | Vulnerability CSV Bulk Import | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ADM-07** | Administrator | Audit Log Review, Search, and Filtering | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ITS-01** | IT Support | IT Support Authentication & Dashboard Access | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ITS-02** | IT Support | Department Creation & IT Asset Registration | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ITS-03** | IT Support | Software Catalogue Item Creation & Manual Asset Linkage | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ITS-04** | IT Support | Software Inventory CSV Bulk Upload | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ITS-05** | IT Support | Asset-Targeted Compliance Verification | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ITS-06** | IT Support | IT Operational Asset Compliance CSV Export | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ITS-07** | IT Support | Administrative Boundary Enforcement (RBAC Denials) | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-SEC-01** | Security Analyst | Security Analyst Authentication & Security Posture Review | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-SEC-02** | Security Analyst | Vulnerability Database Browsing & CVE Inspection | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-SEC-03** | Security Analyst | Organization-Wide Compliance Analysis Execution | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-SEC-04** | Security Analyst | Identification & Filtering of Non-Compliant Assets | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-SEC-05** | Security Analyst | Deterministic Patch Priority Queue Inspection | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-SEC-06** | Security Analyst | Centralized Multi-Parameter Security Search | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-SEC-07** | Security Analyst | Executive PDF Compliance Report Generation | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-ALL-01** | All Roles | In-App Alert Notifications & Read State Management | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |
| **UAT-E2E-01** | Unified Roles | Complete Security Operations Lifecycle (End-to-End) | `[ ] Pass  [ ] Fail` | ____________ | ____/____/2026 |

---

## 3. Detailed UAT Scenarios

### Workflow Group 1: Administrator Operations

#### Scenario ID: `UAT-ADM-01`
- **User Role**: Administrator
- **Scenario Title**: Administrative Authentication & Session Initialization
- **Preconditions**:
  - Application server running and accessible via browser.
  - Active Administrator credentials provisioned (`username: admin`, `password: Admin123!`).
- **Steps**:
  1. Navigate to `/auth/login` in the browser.
  2. Enter Administrator username or email in the `Username or Email` input field.
  3. Enter valid password in the `Password` field.
  4. Click the **Sign In** button.
- **Expected Result**:
  - User is authenticated and redirected to `/dashboard`.
  - Flash message displays: `Welcome back, <username> (ADMINISTRATOR)!`.
  - Top navigation bar displays the current username and role badge `ADMINISTRATOR`.
  - Admin menu links (**Admin Console**, **Audit Logs**, **User Management**) are visible.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ADM-02`
- **User Role**: Administrator
- **Scenario Title**: User Account Creation & Role Assignment
- **Preconditions**:
  - Administrator logged in and on the `/admin/users` page.
- **Steps**:
  1. Click the **+ Create User** button (or navigate to `/admin/users/new`).
  2. Enter `analyst_john` in the **Username** field.
  3. Enter `john.analyst@company.local` in the **Email Address** field.
  4. Enter a strong password (minimum 8 characters, e.g. `AnalystPass2026!`) in the **Password** field.
  5. Select `Security Analyst` from the **Role Assignment** dropdown.
  6. Ensure the **Account Active** checkbox is checked.
  7. Click the **Create Account** button.
- **Expected Result**:
  - System redirects to `/admin/users`.
  - Flash notification displays: `User account 'analyst_john' created successfully.`.
  - The new user appears in the user table with role badge `SECURITY_ANALYST` and status badge `Active`.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ADM-03`
- **User Role**: Administrator
- **Scenario Title**: User Modification & Status Toggle (Account Disabling)
- **Preconditions**:
  - Administrator logged in; user `analyst_john` exists in active state.
- **Steps**:
  1. On `/admin/users`, locate `analyst_john`.
  2. Click the **Edit** button next to `analyst_john`.
  3. Update email to `john.updated@company.local`.
  4. Leave password field blank.
  5. Click **Update Account**.
  6. Return to `/admin/users` and click the **Disable** button for `analyst_john`.
  7. Confirm the browser confirmation prompt.
- **Expected Result**:
  - User details update confirmed by flash message: `User account 'analyst_john' updated successfully.`.
  - Status toggle action updates status to `Disabled` with flash message: `User account has been disabled.`.
  - Attempting to log in as `analyst_john` in an incognito window fails with error: `Your account has been deactivated. Please contact your system administrator.`.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ADM-04`
- **User Role**: Administrator
- **Scenario Title**: Self-Disable Restriction Enforcement
- **Preconditions**:
  - Administrator logged in as `admin`.
- **Steps**:
  1. Navigate to `/admin/users`.
  2. Locate the row corresponding to the currently logged-in `admin` account.
  3. Note that the disable button is hidden or attempting to submit a toggle request against the active admin ID is rejected.
- **Expected Result**:
  - System prevents self-lockout and displays warning: `You cannot disable your own active administrator account.`.
  - Admin account remains `Active`.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ADM-05`
- **User Role**: Administrator
- **Scenario Title**: Manual Vulnerability (CVE) Ingestion & Validation
- **Preconditions**:
  - Administrator logged in.
- **Steps**:
  1. Navigate to `/vulnerabilities/new` via the navigation bar.
  2. Enter `CVE-2023-4863` in **CVE ID**.
  3. Enter `libwebp` in **Affected Software**.
  4. Enter `Google` in **Vendor**.
  5. Enter `Heap buffer overflow in libwebp in Google Chrome before 116.0.5845.187` in **Description**.
  6. Enter `8.8` in **CVSS Score**.
  7. Select `HIGH` in **Severity**.
  8. Enter `< 1.0.3` in **Affected Versions**.
  9. Enter `1.0.3` in **Fixed Version**.
  10. Check **Patch Available** checkbox.
  11. Check **Exploit Available** checkbox.
  12. Select or enter published date `2023-09-12`.
  13. Click **Save Vulnerability Record**.
- **Expected Result**:
  - System creates CVE record and redirects to detail view `/vulnerabilities/<id>`.
  - Flash message: `Vulnerability record 'CVE-2023-4863' created successfully.`.
  - Detail page displays all entered attributes, CVSS gauge 8.8, and badges for Patch Available and Exploit Public.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ADM-06`
- **User Role**: Administrator
- **Scenario Title**: Vulnerability CSV Bulk Import
- **Preconditions**:
  - Administrator logged in; valid CSV file prepared with header:  
    `cve_id,software,vendor,description,cvss_score,severity,affected_versions,fixed_version,patch_available,exploit_available,published_date`
- **Steps**:
  1. Navigate to `/vulnerabilities/import`.
  2. Click **Choose File** and select the prepared CVE CSV file containing 2 new vulnerability records.
  3. Click **Import Vulnerabilities**.
- **Expected Result**:
  - System processes file stream and redirects to `/vulnerabilities/`.
  - Flash message displays: `Successfully imported 2 vulnerability records.`.
  - New CVE records appear in the vulnerability database table.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ADM-07`
- **User Role**: Administrator
- **Scenario Title**: Audit Log Review, Search, and Filtering
- **Preconditions**:
  - Administrator logged in; prior operational actions executed (login, asset creation, user updates).
- **Steps**:
  1. Navigate to `/admin/audit-logs` via the navigation bar.
  2. Verify that the table lists recent events with timestamp, username, action category, IP address, and status.
  3. Filter by Action Category dropdown selecting `USER_CREATED` and click **Filter**.
  4. Clear filter and enter `admin` in the search query field.
- **Expected Result**:
  - Audit trail displays chronologically sorted events.
  - Filtering by category isolates only corresponding action records.
  - Search query isolates events performed by or affecting the specified user.
  - Pagination controls operate correctly when records exceed page size limit.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

### Workflow Group 2: IT Support Operations

#### Scenario ID: `UAT-ITS-01`
- **User Role**: IT Support
- **Scenario Title**: IT Support Authentication & Dashboard Access
- **Preconditions**:
  - Active IT Support user account provisioned (`support_user`).
- **Steps**:
  1. Navigate to `/auth/login`.
  2. Enter IT Support credentials and click **Sign In**.
- **Expected Result**:
  - User successfully logs in and redirects to `/dashboard`.
  - Role badge displays `IT_SUPPORT`.
  - Navigation bar shows **Dashboard**, **IT Assets**, **Software Catalogue**, **Reports**, **Search**, **Notifications**.
  - Admin-only links (**Admin Console**, **Audit Logs**, **User Management**) are NOT displayed.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ITS-02`
- **User Role**: IT Support
- **Scenario Title**: Department Creation & IT Asset Registration
- **Preconditions**:
  - IT Support user logged in.
- **Steps**:
  1. Navigate to `/assets/departments`.
  2. In the **Create Department** form, enter `Finance & Accounting` and description `Enterprise ERP operations`. Click **Create Department**.
  3. Navigate to `/assets/new`.
  4. Fill out the asset form:
     - **Hostname**: `FIN-ERP-SRV01`
     - **IP Address**: `10.20.30.45`
     - **Operating System**: `Red Hat Enterprise Linux`
     - **OS Version**: `9.3`
     - **Department**: Select `Finance & Accounting`
     - **Owner**: `ERP Operations Team`
     - **Asset Type**: `Server`
     - **Criticality**: `CRITICAL`
  5. Click **Create IT Asset**.
- **Expected Result**:
  - Department `Finance & Accounting` created successfully.
  - Asset created and redirects to `/assets/<id>`.
  - Flash message: `Asset 'FIN-ERP-SRV01' created successfully.`.
  - Asset details page shows assigned department, IP, OS, and red badge for `CRITICAL` criticality.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ITS-03`
- **User Role**: IT Support
- **Scenario Title**: Software Catalogue Item Creation & Manual Asset Linkage
- **Preconditions**:
  - IT Support user logged in; asset `FIN-ERP-SRV01` exists.
- **Steps**:
  1. Navigate to `/software/new`.
  2. Enter **Software Name**: `Nginx`, **Vendor**: `F5 NGINX`, **Category**: `Web Server`.
  3. Click **Add Software**.
  4. Navigate to `/assets/` and click on `FIN-ERP-SRV01` to view its detail page.
  5. In the **Link Installed Software** section, select `Nginx (F5 NGINX)` from the dropdown.
  6. Enter **Installed Version**: `1.20.1`.
  7. Click **Link Software**.
- **Expected Result**:
  - Software added to catalogue with flash confirmation.
  - Software linked to `FIN-ERP-SRV01` with flash: `Installed software linked successfully.`.
  - Table on asset detail page displays `Nginx`, version `1.20.1`, and initial status badge `Unknown` (pending compliance scan).
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ITS-04`
- **User Role**: IT Support
- **Scenario Title**: Software Inventory CSV Bulk Upload
- **Preconditions**:
  - IT Support user logged in; assets exist in database.
  - CSV file prepared with header: `hostname,software,vendor,version,category`  
    Example row: `FIN-ERP-SRV01,OpenSSL,OpenSSL Project,1.1.1f,Cryptography`
- **Steps**:
  1. Navigate to `/software/import`.
  2. Select the inventory CSV file.
  3. Click **Import Software Inventory**.
- **Expected Result**:
  - System parses CSV, verifies hostname and software records, and creates software association.
  - Redirects to `/assets/` with success message: `Successfully imported 1 software inventory records.`.
  - Viewing `FIN-ERP-SRV01` shows both `Nginx` and `OpenSSL 1.1.1f` installed.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ITS-05`
- **User Role**: IT Support
- **Scenario Title**: Asset-Targeted Compliance Verification
- **Preconditions**:
  - Asset `FIN-ERP-SRV01` has installed software associated.
- **Steps**:
  1. Navigate to the asset detail page for `FIN-ERP-SRV01`.
  2. Click the **Run Compliance Scan** button specifically for this asset.
- **Expected Result**:
  - Single-asset scan runs and redirects to `/compliance/assets/<id>`.
  - Flash message indicates compliance analysis completion and count of findings.
  - Status reflects actual vulnerability correlation for each installed package.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ITS-06`
- **User Role**: IT Support
- **Scenario Title**: IT Operational Asset Compliance CSV Export
- **Preconditions**:
  - IT Support user logged in; assets and software inventory present in system.
- **Steps**:
  1. Navigate to `/reports/`.
  2. Locate the card **Asset-Wise Compliance Inventory Report**.
  3. Click the **CSV** export button.
- **Expected Result**:
  - Browser downloads `asset_compliance_report.csv`.
  - File opens in spreadsheet software (Excel, LibreOffice) displaying columns: `Asset ID,Hostname,IP Address,Department,Criticality,Software Name,Installed Version,Compliance Status,Associated CVE`.
  - Contains all installed software items and accurate asset linkages.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-ITS-07`
- **User Role**: IT Support
- **Scenario Title**: Administrative Boundary Enforcement (RBAC Denials)
- **Preconditions**:
  - IT Support user logged in.
- **Steps**:
  1. Attempt to navigate directly to `/admin/users`.
  2. Attempt to navigate directly to `/admin/audit-logs`.
  3. Attempt to navigate directly to `/vulnerabilities/new`.
- **Expected Result**:
  - Server rejects access with HTTP `403 Forbidden` response for each restricted route.
  - Error page clearly explains authorization restriction without crashing.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

### Workflow Group 3: Security Analyst Operations

#### Scenario ID: `UAT-SEC-01`
- **User Role**: Security Analyst
- **Scenario Title**: Security Analyst Authentication & Security Posture Review
- **Preconditions**:
  - Active Security Analyst credentials (`analyst_user`).
- **Steps**:
  1. Navigate to `/auth/login` and log in.
  2. Inspect `/dashboard`.
- **Expected Result**:
  - Successful authentication; badge displays `SECURITY_ANALYST`.
  - Dashboard displays executive cards: **Total IT Assets**, **Compliant Assets**, **Non-Compliant Assets**, **Unknown Assets**, **Compliance Rate**, and **Critical Vulnerabilities**.
  - Interactive charts (Compliance Rate Donut & Department Distribution Bar Chart) render correctly.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-SEC-02`
- **User Role**: Security Analyst
- **Scenario Title**: Vulnerability Database Browsing & CVE Inspection
- **Preconditions**:
  - Security Analyst logged in; vulnerability records exist.
- **Steps**:
  1. Navigate to `/vulnerabilities/`.
  2. Enter `OpenSSL` in the **Filter by Software** field and select Severity `CRITICAL`. Click **Filter**.
  3. Click **View Details** on any matching CVE record.
- **Expected Result**:
  - List filters to only matching OpenSSL Critical vulnerabilities.
  - Detail page `/vulnerabilities/<id>` displays description, CVSS metrics, affected version ranges, fixed version, patch availability, and exploit status.
  - Administrative buttons (**Edit**, **Delete**, **Import**) are NOT visible to the Analyst.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-SEC-03`
- **User Role**: Security Analyst
- **Scenario Title**: Organization-Wide Compliance Analysis Execution
- **Preconditions**:
  - Security Analyst logged in; assets and vulnerability records present.
- **Steps**:
  1. Navigate to `/compliance/`.
  2. Click the primary action button: **Run Compliance Scan**.
- **Expected Result**:
  - System executes version comparison engine across all installed software records and active CVE definitions.
  - Page refreshes with flash message: `Compliance analysis completed. Scanned X software record(s). Detected Y non-compliant vulnerability finding(s).`.
  - Executive summary statistics (Total Scanned, Compliant, Non-Compliant, Unknown) update immediately.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-SEC-04`
- **User Role**: Security Analyst
- **Scenario Title**: Identification & Filtering of Non-Compliant Assets
- **Preconditions**:
  - Non-compliant findings exist in system following compliance scan.
- **Steps**:
  1. Navigate to `/compliance/non-compliant`.
  2. Inspect the table of active findings.
  3. Select `CRITICAL` in the **Severity** filter dropdown and click **Apply Filters**.
- **Expected Result**:
  - Table lists non-compliant findings with Asset Hostname, IP, Software Name, Installed Version, Matching CVE, CVSS Score, Severity Badge, and Fixed Version.
  - Filtering restricts view strictly to findings matching selected severity level.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-SEC-05`
- **User Role**: Security Analyst
- **Scenario Title**: Deterministic Patch Priority Queue Inspection
- **Preconditions**:
  - Security Analyst logged in; non-compliant findings exist.
- **Steps**:
  1. Navigate to `/compliance/priority`.
  2. Inspect the **Patch Priority Queue** table.
  3. Examine the top-ranked item's priority score (0–100) and factor explanation badge.
- **Expected Result**:
  - Items are sorted in descending order of composite priority score.
  - Priority tiers (`CRITICAL` >= 70, `HIGH` 50-69, `MEDIUM` 30-49, `LOW` < 30) display distinct color styling.
  - Factor breakdown shows points contributed by CVSS, asset criticality, exploit availability, affected asset count, vulnerability age, and patch availability.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-SEC-06`
- **User Role**: Security Analyst
- **Scenario Title**: Centralized Multi-Parameter Security Search
- **Preconditions**:
  - Security Analyst logged in.
- **Steps**:
  1. Navigate to `/search/`.
  2. Enter hostname keyword or select `CRITICAL` criticality and `NON_COMPLIANT` status.
  3. Click the **Search** button.
- **Expected Result**:
  - System returns matching assets and vulnerabilities with deep-link buttons.
  - Result count and pagination indicators update accurately.
  - Clicking any search result navigates directly to the target asset or compliance detail view.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

#### Scenario ID: `UAT-SEC-07`
- **User Role**: Security Analyst
- **Scenario Title**: Executive PDF Compliance Report Generation
- **Preconditions**:
  - Security Analyst logged in; compliance scan completed.
- **Steps**:
  1. Navigate to `/reports/`.
  2. Under **Critical & High Vulnerability Risk Report**, click **PDF**.
  3. Under **Overall Compliance Report**, click **PDF**.
- **Expected Result**:
  - Browser prompts to save or opens formatted PDF documents (`critical_vulnerability_report.pdf` and `overall_compliance_report.pdf`).
  - PDFs include formal header, generation timestamp, summary metrics table, and detailed records formatted cleanly with ReportLab.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

### Workflow Group 4: Common Cross-Role Scenarios

#### Scenario ID: `UAT-ALL-01`
- **User Role**: All Roles (Administrator, Security Analyst, IT Support)
- **Scenario Title**: In-App Alert Notifications & Read State Management
- **Preconditions**:
  - User logged in; automated notifications generated by compliance scans or vulnerability additions.
- **Steps**:
  1. Observe the notification bell icon in the top-right navigation bar.
  2. Verify that an unread badge indicator displays if unread alerts exist.
  3. Click the bell icon to navigate to `/notifications/`.
  4. Click **Mark as Read** on an individual notification.
  5. Click **Mark All as Read** button.
- **Expected Result**:
  - Notification list displays high/critical severity alerts with title, timestamp, and message.
  - Marking single notification changes its status to read.
  - "Mark All as Read" clears the unread badge from the navbar.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

### Workflow Group 5: Complete End-to-End Enterprise Lifecycle

#### Scenario ID: `UAT-E2E-01`
- **User Role**: Multi-Role Hand-Off (Administrator & IT Support & Security Analyst)
- **Scenario Title**: Complete Operational Security Lifecycle
- **Preconditions**:
  - Fresh or clean database environment.
- **Steps**:
  1. **[IT Support]**: Log in and register asset `PROD-DB-PRIMARY` (`Server`, `CRITICAL`, IP `10.100.1.5`).
  2. **[IT Support]**: Create software catalogue entry `PostgreSQL` and link version `12.4` to `PROD-DB-PRIMARY`.
  3. **[Administrator]**: Log in and ingest CVE `CVE-2020-25695` (`PostgreSQL`, CVSS 8.8, `CRITICAL`, affected `< 12.5`, fixed `12.5`, patch=True, exploit=True).
  4. **[Security Analyst]**: Log in, run global compliance scan at `/compliance/run`.
  5. **[Security Analyst]**: Verify `PROD-DB-PRIMARY` appears as `Non-Compliant` in `/compliance/non-compliant`.
  6. **[Security Analyst]**: Verify `CVE-2020-25695` is ranked in `/compliance/priority` with tier `CRITICAL`.
  7. **[Security Analyst]**: Export **Patch Priority Queue Report** in CSV and PDF at `/reports/`.
  8. **[Administrator]**: Log in and verify full audit trail at `/admin/audit-logs` recording the complete chain of events.
- **Expected Result**:
  - Every transition across roles succeeds deterministically without data corruption or permission bypass.
  - End-to-end flow from asset registration to risk prioritization and executive reporting completes cleanly.
- **Actual Result Placeholder**:
  ```
  [ ] Matches Expected
  Notes: ____________________________________________________________________
  ```
- **Pass/Fail Placeholder**:
  ```
  Status: [ ] Pass   [ ] Fail   [ ] Blocked
  Tested By: ___________________ Date: _______________
  ```

---

## 4. Acceptance Sign-Off Form

To be completed by designated stakeholders upon completion of manual testing:

| Stakeholder Role | Name | Signature | Decision (Accept / Reject) | Date |
| :--- | :--- | :--- | :---: | :--- |
| **Lead Administrator** | _______________________ | _______________________ | `[ ] Accept  [ ] Reject` | ____/____/2026 |
| **Lead Security Analyst** | _______________________ | _______________________ | `[ ] Accept  [ ] Reject` | ____/____/2026 |
| **IT Support Lead** | _______________________ | _______________________ | `[ ] Accept  [ ] Reject` | ____/____/2026 |
| **System QA Lead** | _______________________ | _______________________ | `[ ] Accept  [ ] Reject` | ____/____/2026 |

**Comments / Remediation Notes:**  
________________________________________________________________________________________________________________________  
________________________________________________________________________________________________________________________  
________________________________________________________________________________________________________________________
