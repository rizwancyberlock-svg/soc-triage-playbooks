---
id: PB-NET-002
title: Large Outbound Transfer / Exfiltration Tools
severity: HIGH
mitre: T1048, T1567.002, T1560.001
related_rules: net_large_outbound_transfer, win_rclone_exfiltration, win_archive_with_password, dlp_personal_cloud_upload, m365_mass_file_download
---

# Large Outbound Transfer / Exfiltration Tools

> Double-extortion ransomware steals data first. Rclone, MEGA and password-protected archives are the usual tools.

## Triage decision tree
```mermaid
flowchart TD
  A[Large outbound / exfil tool] --> B{Destination is sanctioned<br/>backup / SaaS / CDN?}
  B -- Yes --> C[Benign - add to exclusion, close]
  B -- No --> D{Exfil tool or archive staging<br/>on the source host?}
  D -- Yes --> E[Likely exfiltration - isolate host<br/>preserve evidence]
  D -- No --> F{Server or workstation?}
  F -- Server --> E
  F -- Workstation --> G[Ask user / manager<br/>check DLP events]
```

## Investigation steps
1. Destination IP/domain, ASN, and service (MEGA, Dropbox, attacker VPS).
2. Process responsible for the traffic (EDR network events on the host).
3. Staging: archives created before the transfer (`7z a -p`, `rar a -hp`), mapped shares accessed.
4. Which data? File paths in archive commands / rclone config, DLP incidents for the same user.

## Containment & response
- Block the destination; isolate the host if exfil is ongoing.
- Disable the account used; revoke cloud storage tokens found in rclone config.
- Treat as precursor to ransomware - run the ransomware playbook checks fleet-wide.

## Escalation criteria
Confirmed exfiltration of business data → IR + legal/privacy.

## Evidence to collect
Flow/proxy logs with byte counts, tool command lines and config, archive names, data inventory.
