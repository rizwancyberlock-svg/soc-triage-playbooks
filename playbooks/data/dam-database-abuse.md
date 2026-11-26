---
id: PB-DAT-001
title: Database Abuse (Guardium DAM)
severity: HIGH
mitre: T1213.006, T1485, T1098, T1059
related_rules: dam_bulk_data_access_single_user, dam_off_hours_sensitive_access, dam_service_account_interactive_tool, dam_privilege_grant, dam_destructive_ddl, dam_delete_without_where, dam_os_command_execution, dam_credential_table_access, dam_audit_disabled
---

# Database Abuse (Guardium DAM)

> The database is usually the attacker's final objective. DAM sees the SQL that network tools never will.

## Triage decision tree
```mermaid
flowchart TD
  A[DAM alert] --> B{Which pattern?}
  B -- "Bulk SELECT / off-hours" --> C{Known batch / ETL / report job?}
  C -- Yes --> D[Benign - exclude job account, close]
  C -- No --> E[Possible data theft - identify client + human]
  B -- "App account from SSMS / sqlplus" --> E
  B -- "GRANT / CREATE USER" --> F{Ticket exists?}
  F -- Yes --> D
  F -- No --> G[Revoke, investigate DBA account]
  B -- "DROP / DELETE w/o WHERE / audit off / xp_cmdshell" --> H[CRITICAL - contact DBA on call<br/>preserve evidence]
```

## Investigation steps
1. From Guardium: DB user, OS user, client IP/hostname, source program, full SQL, object names, rows returned.
2. Map the client IP to a host and logged-on human (Windows logon events / VPN logs).
3. Data sensitivity of the objects (PII, cardholder, credentials) - check Guardium classification.
4. Pattern over time: is this a new behaviour for this DB user? Compare 30-day baseline in Guardium reports.
5. For `xp_cmdshell` / `COPY FROM PROGRAM`: pivot to the DB server process telemetry (`win_sqlserver_spawns_shell`).

## Containment & response
- Lock or change the password of the DB account; kill active sessions.
- For app accounts used interactively: rotate the credential in the vault and restrict it to the app server IPs.
- Restore audit settings; restore dropped/deleted data from backup.
- Use Guardium S-GATE / blocking policy for repeated abuse.

## Escalation criteria
Sensitive data accessed by an unexplained human, destructive SQL in production, audit disablement, or OS command execution → IR + data owner.

## Evidence to collect
Guardium session report (full SQL), client host details, row counts, data classification.
