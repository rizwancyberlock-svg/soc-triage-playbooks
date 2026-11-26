---
id: PB-END-001
title: Suspicious PowerShell Execution
severity: HIGH
mitre: T1059.001, T1562.001, T1105
related_rules: win_powershell_encoded_command, win_powershell_download_cradle, win_powershell_amsi_bypass, win_powershell_suspicious_flags, win_defender_tampering_powershell
---

# Suspicious PowerShell Execution

> Encoded commands, download cradles, AMSI bypasses and Defender tampering. Decode first, judge second.

## When this fires
Any rule in `related_rules`. Severity rises when several fire on the same host within minutes.

## Triage decision tree
```mermaid
flowchart TD
  A[PowerShell alert] --> B[Decode the payload<br/>Base64 / UTF-16LE]
  B --> C{Parent process?}
  C -- "Office, browser, mshta, wscript, w3wp" --> D[HIGH: likely initial access<br/>Containment]
  C -- "SCCM, Intune, RMM agent" --> E{Decoded content matches<br/>known management script?}
  E -- Yes --> F[Benign - allowlist by parent + hash]
  E -- No --> G[Possible abuse of management tooling<br/>escalate]
  C -- "explorer.exe / cmd (user)" --> H{Downloads or AMSI bypass<br/>in decoded content?}
  H -- Yes --> D
  H -- No --> I[Ask user / owner, monitor]
```

## Investigation steps
1. **Decode**: `-EncodedCommand` is Base64 of UTF-16LE. In CyberChef: *From Base64 → Decode text (UTF-16LE)*. Repeat for nested layers.
2. Extract IOCs from decoded content: URLs, domains, IPs, file paths, scheduled task names.
3. Process tree - parent and grandparent:
   ```
   metadata.event_type = "PROCESS_LAUNCH" and principal.hostname = "<HOST>"
   ```
4. Network: did the host connect to the extracted domains/IPs?
   ```
   principal.hostname = "<HOST>" and (target.hostname = "<DOMAIN>" or target.ip = "<IP>")
   ```
5. Persistence check: scheduled tasks, Run keys, services created on the host in ±1h.

## True vs false positive
| Likely true positive | Likely false positive |
|---|---|
| Parent is Office / browser / script host | Parent is a signed management agent |
| Decoded content downloads and executes | Decoded content is inventory/config |
| AMSI bypass or Defender exclusions | Runs fleet-wide at the same time daily |
| Connections to new / low-reputation domains | Domain is your own infrastructure |

## Containment & response
- Isolate the host via EDR if a payload executed or C2 is observed.
- Block extracted domains/IPs/hashes; hunt for them fleet-wide.
- Re-enable Defender settings and remove exclusions if tampering occurred.

## Escalation criteria
Payload executed, network connection to attacker infrastructure, AMSI/Defender tampering, or the same activity on more than one host → IR.

## Evidence to collect
Full command line, decoded script, process tree, network connections, dropped files (hashes).
