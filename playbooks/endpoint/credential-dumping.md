---
id: PB-END-002
title: Credential Dumping (LSASS, SAM, NTDS, DCSync)
severity: CRITICAL
mitre: T1003.001, T1003.002, T1003.003, T1003.006, T1558.003
related_rules: win_lsass_credential_dump, win_sam_hive_dump, win_ntds_dit_extraction, win_dcsync_tooling, win_kerberoasting_tooling, mde_credential_theft_alert
---

# Credential Dumping (LSASS, SAM, NTDS, DCSync)

> If this is real, the attacker is past initial access and harvesting credentials for lateral movement. Speed matters more than certainty.

## Triage decision tree
```mermaid
flowchart TD
  A[Credential dumping alert] --> B{Authorized test / IR activity<br/>with ticket?}
  B -- Yes --> C[Benign - document, close]
  B -- No --> D{Target: domain controller<br/>or NTDS / DCSync?}
  D -- Yes --> E[CRITICAL: assume domain-wide compromise<br/>engage IR immediately]
  D -- No --> F[Isolate host<br/>identify all accounts logged on]
  F --> G[Reset those accounts' credentials<br/>hunt for lateral movement]
```

## Investigation steps
1. Confirm execution: did the process complete, and was a dump file written? (`.dmp` in Temp, `ntds.dit` copies, `SAM`/`SYSTEM` hive files)
2. Which accounts were exposed? Every account with an active session on the host - especially admins and service accounts:
   ```
   metadata.event_type = "USER_LOGIN" and target.hostname = "<HOST>" and security_result.action = "ALLOW"
   ```
3. How did the attacker get admin rights on this host? Work backwards: parent process, logon session, initial access.
4. Exfil of the dump: file transfer from the host shortly after (SMB, HTTP upload, rclone).
5. Lateral movement since: new logons from this host to others (RDP, SMB, WinRM, PsExec).

## Containment & response
1. Isolate the host (EDR network containment).
2. Reset passwords of every exposed account; for DC compromise also reset **KRBTGT twice** (10+ hours apart) per Microsoft guidance.
3. Disable compromised service accounts or rotate their secrets in PAM.
4. Hunt for the same tool hash/command line fleet-wide.

## Escalation criteria
Always escalate to IR. DCSync / NTDS extraction = major incident.

## Evidence to collect
Memory image of the host (if possible), command lines, dump file paths/hashes, logon sessions, lateral movement timeline.
