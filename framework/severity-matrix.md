# Severity & Priority Matrix

Rule severity describes the *behaviour*. Incident priority also depends on the *asset* and *confidence*. Use this matrix to set priority.

| Rule severity ↓ / Asset criticality → | Tier 0 (DC, PAM, HSM, CA, IdP) | Tier 1 (prod servers, DBs, cloud admin) | Tier 2 (workstations, dev) |
|---|---|---|---|
| **CRITICAL** | P1 | P1 | P2 |
| **HIGH** | P1 | P2 | P3 |
| **MEDIUM** | P2 | P3 | P4 |
| **LOW / INFO** | P3 | P4 | P4 |

**Raise one level** if: privileged account involved · multiple hosts · confirmed data access · active C2.
**Lower one level** if: activity was blocked/prevented and no follow-on activity exists.

## Response time targets

| Priority | Acknowledge | Triage complete | Containment decision |
|---|---|---|---|
| P1 | 15 min | 1 h | 1 h |
| P2 | 30 min | 4 h | 8 h |
| P3 | 4 h | 1 business day | - |
| P4 | 1 business day | 3 business days | - |

Align these with your SOC SLA and compliance obligations (e.g. PCI DSS 10.7 / 12.10, SOC 2 CC7.3-CC7.4).
