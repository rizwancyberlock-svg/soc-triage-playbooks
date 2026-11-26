---
id: PB-END-003
title: Ransomware Precursors and Encryption
severity: CRITICAL
mitre: T1490, T1486, T1562.001, T1562.009, T1489
related_rules: win_inhibit_system_recovery, win_mass_file_modification, win_security_tool_killed, win_safe_mode_boot_set, win_defender_tampering_powershell, mde_ransomware_alert, edr_same_threat_multiple_hosts
---

# Ransomware Precursors and Encryption

> Shadow-copy deletion, security tools being killed and mass file changes mean encryption is minutes away or already running. **Contain first, investigate second.**

## Triage decision tree
```mermaid
flowchart TD
  A[Ransomware indicator] --> B{Mass file modification<br/>or ransom notes present?}
  B -- Yes --> C[ENCRYPTION IN PROGRESS<br/>isolate host + declare major incident]
  B -- No --> D{Approved backup / maintenance<br/>activity?}
  D -- Yes --> E[Benign - document, close]
  D -- No --> F[Isolate host NOW<br/>then investigate]
  C --> G[Check other hosts for same indicators<br/>within the last hour]
  F --> G
```

## Investigation steps (after isolation)
1. Scope: same command lines / hashes / threat names on other hosts:
   ```
   target.process.command_line = /vssadmin|wbadmin|bcdedit|shadowcopy/ nocase
   ```
2. Account used: which user ran the commands? Usually a domain admin or a compromised service account - that account is the attacker's key.
3. Deployment method: GPO, PsExec, scheduled tasks, WMI, RMM tool, or EDR/RMM console abuse.
4. Exfiltration before encryption (double extortion): rclone/MEGA, large outbound transfers.
5. Initial access: VPN brute force, exposed RDP, phishing, unpatched edge device.

## Containment & response
1. Network-isolate affected hosts via EDR; if spreading, isolate segments / disable VPN.
2. Disable the account(s) used for deployment; reset KRBTGT if domain admin was used.
3. Protect backups: take them offline / verify immutability.
4. Do **not** reboot encrypted hosts (keys may be in memory); do not delete ransom notes.

## Escalation criteria
Always a major incident. Notify IR lead, management and legal per the incident response plan.

## Evidence to collect
Ransom note, encrypted file samples, binary hashes, command lines, deployment account, exfil indicators, memory captures.
