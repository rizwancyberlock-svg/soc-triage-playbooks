---
id: PB-END-005
title: Web Shell / Exploited Web Application
severity: CRITICAL
mitre: T1505.003, T1190
related_rules: win_webserver_spawns_shell, lnx_webserver_spawns_shell, web_webshell_access, web_command_injection, win_sqlserver_spawns_shell
---

# Web Shell / Exploited Web Application

> A web server process launching `cmd`, `whoami` or `bash` means someone is executing commands through your application.

## Triage decision tree
```mermaid
flowchart TD
  A[Web server spawned shell] --> B{Command matches documented<br/>application behaviour?}
  B -- Yes --> C[Benign - allowlist exact command, close]
  B -- No --> D{Recon or download commands?<br/>whoami, net, certutil, curl}
  D -- Yes --> E[Active exploitation - Containment]
  D -- No --> F[Find triggering HTTP request<br/>in WAF / web logs]
  F --> E
```

## Investigation steps
1. Find the triggering request: correlate the process timestamp with web/WAF logs for the same host (URI, source IP, user agent).
   ```
   metadata.event_type = "NETWORK_HTTP" and target.hostname = "<SITE>"
   ```
2. Look for new or recently modified script files in the web root (`.aspx`, `.php`, `.jsp`) - that's the web shell.
3. Identify the vulnerability: known CVE for the product/version (Exchange, Confluence, MOVEit, Ivanti ...)?
4. Post-exploitation: credential dumping, new accounts, lateral movement from the server.

## Containment & response
- Take the application offline or block the attacker IPs at the WAF; isolate the server if post-exploitation occurred.
- Remove the web shell (after collecting it), patch the vulnerability.
- Rotate credentials stored on the server (app config, connection strings, service accounts).

## Escalation criteria
Always IR when commands executed. Internet-facing systems = potential data breach notification.

## Evidence to collect
Web shell file, web/WAF logs, process tree, attacker IPs, vulnerability details.
