# Escalation & Shift Handover

## Escalation matrix

| Situation | Escalate to | How |
|---|---|---|
| P1 incident / ransomware / DC or HSM compromise | IR lead + SOC manager | Phone call + incident channel |
| Confirmed data exposure (PII, PCI, PHI) | IR lead + Privacy officer / DPO | Incident ticket + email |
| Insider-risk indicators | SOC manager → HR / Legal | Restricted ticket, no broad channels |
| Cloud account compromise | Cloud security on-call | Pager + ticket |
| Database / DAM critical alert | DBA on-call + data owner | Pager + ticket |
| PAM / HSM critical alert | IAM / crypto custodian | Phone call |
| Detection is too noisy | Detection engineering | Tuning request ticket |

**Rule of thumb:** if in doubt on P1/P2, escalate. A false alarm costs minutes; a missed breach costs months.

## Shift handover template

```markdown
## Shift handover - <date> <shift>

### Open incidents
| Ticket | Priority | Status | Next action | Owner |
|---|---|---|---|---|

### Alerts awaiting information
| Alert | Waiting on | Since |
|---|---|---|

### Notable observations
- <campaigns, noisy rules, log source outages>

### Tuning requests raised
- <rule> - <reason>
```
