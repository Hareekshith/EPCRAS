# EPCRAS Patch Compliance Engine Documentation

## Overview & Architecture

The **Enterprise Patch Compliance & Risk Assessment System (EPCRAS)** Patch Compliance Engine automates the detection of security risks by evaluating installed software versions against known security advisories in the Vulnerability Database.

The engine follows a strict service-oriented architecture:

```
+---------------------+     +-----------------------+     +-----------------------+
| Installed Software  | --> |  Compliance Analysis  | <-- | Vulnerability DB      |
| Inventory           |     |  Service Layer        |     | (CVE, CVSS, Ranges)   |
+---------------------+     +-----------------------+     +-----------------------+
                                        |
                                        v
                            +-----------------------+
                            | Version Utility       |
                            | (packaging.version)   |
                            +-----------------------+
                                        |
                                        v
                            +-----------------------+
                            | ComplianceResult      |
                            | (COMPLIANT,           |
                            |  NON_COMPLIANT,       |
                            |  UNKNOWN)             |
                            +-----------------------+
```

---

## 1. Version Comparison Algorithm

### Rule: Strict Non-Lexicographical Comparison
Under no circumstances does the EPCRAS Compliance Engine use raw string or lexicographical comparisons (e.g., `"2.10.0" > "2.2.0"` would incorrectly evaluate to `False` under string comparison). 

All versions are parsed into semantically structured `packaging.version.Version` objects adhering to PEP 440 specifications.

### Version Parsing Strategy
1. **Normalization**: Strips leading `v`/`V` prefixes and whitespace.
2. **Parsing**: Uses `packaging.version.parse()` to decompose version strings into numeric tuples (Major, Minor, Patch, Micro).
3. **Fallback Safety**: If a version string contains arbitrary unparseable characters or cannot be reliably interpreted, parsing returns `None`.

### Supported Vulnerability Range Expressions
The engine supports common vulnerability advisory range syntaxes:
- **Explicit Operators**: `<`, `<=`, `>`, `>=`, `==` (e.g., `< 1.3.2`, `<= 2.14.1`)
- **Bounded Ranges (Comma Separated)**: `">= 2.0, <= 2.14.1"`
- **Textual Bounded Ranges**: `"5.3.0 to 5.3.17"`, `"5.6.0 - 5.6.1"`
- **Space Bounded Ranges**: `"5.6.0 <= 5.6.1"`
- **Exact Version Matching**: `"1.0.0"`

---

## 2. Compliance Decision Matrix

For each installed software instance:

| Condition | Compliance Status | Rationale |
| :--- | :--- | :--- |
| Installed version $\ge$ `fixed_version` | `COMPLIANT` | Software has received patch containing the fix. |
| Installed version falls within an affected vulnerability range | `NON_COMPLIANT` | Software is exposed to active CVE vulnerability. |
| No vulnerability records exist for the software name | `UNKNOWN` | Advisory data is missing or incomplete. |
| Installed version or vulnerability range string is unparseable | `UNKNOWN` | Version cannot be reliably compared; system avoids false assurances. |

---

## 3. Non-Compliant Finding Data Schema

When an installation is evaluated as `NON_COMPLIANT`, a `ComplianceResult` entity persists the following details:

- **Asset**: Hostname and internal Asset ID
- **Software**: Software application name and vendor
- **Installed Version**: Exact software version detected on asset
- **CVE ID**: Standardized CVE Identifier (e.g. `CVE-2021-44228`)
- **CVSS Score**: CVSS v3 score (0.0 to 10.0)
- **Severity**: Risk classification (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- **Fixed Version**: Version containing remediation patch (if available)
- **Patch Availability**: Boolean flag indicating if vendor patch is published

---

## 4. Execution & Audit Trail

1. **Triggering Analysis**: Analysis can be executed across all assets or targeted to a single asset via `run_compliance_analysis()`.
2. **Audit Logging**: Every analysis run records a structured `COMPLIANCE` audit log event recording scanned installation count, non-compliant finding count, and timestamp.
3. **UI Integration**: Real-time compliance posture metrics (Compliance Rate %, severity exposure counts, non-compliant asset listings) are presented on the `/compliance/` dashboard.
