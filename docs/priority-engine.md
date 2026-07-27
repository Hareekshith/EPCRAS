# EPCRAS Patch Priority Engine — Mathematical Specification & Scoring Model

## Executive Overview
The **EPCRAS Patch Priority Engine** provides a transparent, deterministic, and fully explainable scoring algorithm for prioritizing software patch deployment across enterprise IT infrastructure. Designed for academic review and operational auditability, the engine evaluates each vulnerability by normalizing six distinct risk factors before computing a weighted priority score from **0 to 100**.

> [!NOTE]
> The prioritization model is strictly mathematical and rule-based. It does **not** rely on non-deterministic machine learning, stochastic estimations, or black-box heuristics.

---

## 1. Weight Distribution Matrix

The scoring engine allocates 100 percentage points across six factors based on enterprise risk management priorities:

| Factor | Weight ($W_i$) | Rationale |
| :--- | :---: | :--- |
| **CVSS Score** | **35%** ($0.35$) | Baseline severity of vulnerability (NVD / CVE standard). |
| **Asset Criticality** | **25%** ($0.25$) | Exposure of critical mission infrastructure (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| **Exploit Availability** | **15%** ($0.15$) | Active threat vector presence (public proof-of-concept / wild exploits). |
| **Affected Asset Count** | **10%** ($0.10$) | Blast radius and operational surface area across the enterprise. |
| **Vulnerability Age** | **10%** ($0.10$) | Exposure duration since public disclosure (days since publication). |
| **Patch Availability** | **5%** ($0.05$) | Remediation readiness (actionability of vendor fix). |

---

## 2. Factor Normalization Functions

Each factor $F_i$ is mapped to a normalized value $N_i \in [0.0, 1.0]$ prior to weighting.

### 2.1 CVSS Score Normalization ($N_{\text{cvss}}$)
Given a CVSS $v \in [0.0, 10.0]$:
$$N_{\text{cvss}} = \frac{v}{10.0}$$

### 2.2 Asset Criticality Normalization ($N_{\text{crit}}$)
Evaluated as the maximum criticality among all active assets affected by the vulnerability:
$$N_{\text{crit}} = \begin{cases}
1.00 & \text{if max criticality is } \mathbf{CRITICAL} \\
0.75 & \text{if max criticality is } \mathbf{HIGH} \\
0.50 & \text{if max criticality is } \mathbf{MEDIUM} \\
0.25 & \text{if max criticality is } \mathbf{LOW} \\
0.00 & \text{if no assets affected}
\end{cases}$$

### 2.3 Exploit Availability Normalization ($N_{\text{exploit}}$)
$$N_{\text{exploit}} = \begin{cases}
1.0 & \text{if public exploit is available} \\
0.0 & \text{otherwise}
\end{cases}$$

### 2.4 Affected Asset Count Normalization ($N_{\text{assets}}$)
Let $A_{\text{vuln}}$ be the number of non-compliant assets affected by this vulnerability, and $A_{\text{total}}$ be the total IT asset inventory count:
$$N_{\text{assets}} = \min\left(1.0, \frac{A_{\text{vuln}}}{\max(1, A_{\text{total}})}\right)$$
*(If $A_{\text{total}} = 0$, $N_{\text{assets}} = 0.0$)*

### 2.5 Vulnerability Age Normalization ($N_{\text{age}}$)
Let $D$ be the number of days elapsed between the vulnerability's published date and current UTC timestamp. Exposure risk scales linearly up to 365 days (1 year):
$$N_{\text{age}} = \min\left(1.0, \frac{\max(0, D)}{365.0}\right)$$
*(If published date is unlisted, defaults to $N_{\text{age}} = 0.50$)*

### 2.6 Patch Availability Normalization ($N_{\text{patch}}$)
$$N_{\text{patch}} = \begin{cases}
1.0 & \text{if vendor patch is available} \\
0.0 & \text{otherwise}
\end{cases}$$

---

## 3. Final Composite Score & Classification

### 3.1 Mathematical Scoring Formula
The final priority score $S \in [0, 100]$ is computed as:
$$S = \text{round}\left(100 \times \sum_{i=1}^{6} W_i N_i\right)$$

Expanding the equation:
$$S = \text{round}\left(100 \times \left(0.35 N_{\text{cvss}} + 0.25 N_{\text{crit}} + 0.15 N_{\text{exploit}} + 0.10 N_{\text{assets}} + 0.10 N_{\text{age}} + 0.05 N_{\text{patch}}\right)\right)$$

### 3.2 Priority Categorization Scale

| Score Range | Priority Tier | Recommended SLA Action |
| :---: | :---: | :--- |
| **75 – 100** | **CRITICAL** | Immediate emergency patch deployment (< 24 hours). |
| **50 – 74** | **HIGH** | High-priority patch maintenance (< 7 days). |
| **25 – 49** | **MEDIUM** | Scheduled maintenance window (< 30 days). |
| **0 – 24** | **LOW** | Routine update cycle. |

---

## 4. Worked Example Calculation

### Scenario: `CVE-2021-44228` (Log4Shell)
- **CVSS Score**: $10.0$ $\implies N_{\text{cvss}} = 1.0$
- **Affected Assets**: $14$ out of $20$ total assets $\implies N_{\text{assets}} = \frac{14}{20} = 0.70$
- **Max Affected Asset Criticality**: `CRITICAL` $\implies N_{\text{crit}} = 1.0$
- **Exploit Available**: `True` $\implies N_{\text{exploit}} = 1.0$
- **Published Date**: 1,200 days ago (capped at 365 days) $\implies N_{\text{age}} = 1.0$
- **Patch Available**: `True` $\implies N_{\text{patch}} = 1.0$

### Score Computation:
$$\begin{aligned}
S &= \text{round}\Big(100 \times \big(0.35(1.0) + 0.25(1.0) + 0.15(1.0) + 0.10(0.70) + 0.10(1.0) + 0.05(1.0)\big)\Big) \\
&= \text{round}\Big(100 \times \big(0.35 + 0.25 + 0.15 + 0.07 + 0.10 + 0.05\big)\Big) \\
&= \text{round}\big(100 \times 0.97\big) \\
&= \mathbf{97} \quad (\mathbf{CRITICAL})
\end{aligned}$$

### Explanation Output:
```text
Score: 97/100
Priority: CRITICAL

Factors:
- CVSS 10.0 (35.0 pts)
- Critical asset affected (25.0 pts)
- Public exploit available (15.0 pts)
- 14 assets affected (7.0 pts)
- Published over 365 days ago (10.0 pts)
- Vendor patch available (5.0 pts)
```

---

## 5. Academic Review Defense

1. **Determinism**: Given identical database state, the algorithm produces identical scores every run.
2. **Auditability**: Every point earned is traceable back to its individual factor formula $W_i \times N_i$.
3. **No Machine Learning Drift**: Avoids bias or unpredictable scoring shifts inherent to black-box models.
