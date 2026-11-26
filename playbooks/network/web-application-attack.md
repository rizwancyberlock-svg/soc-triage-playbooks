---
id: PB-NET-003
title: Web Application Attack (WAF)
severity: HIGH
mitre: T1190, T1595.002
related_rules: web_sqli_attempt, web_log4shell_jndi, web_path_traversal, web_command_injection, web_ssrf_cloud_metadata, web_waf_block_spike, f5_asm_attack_passed_transparent, azwaf_detection_mode_match, fweb_high_severity_attack, hd_waf_attack_spike
---

# Web Application Attack (WAF)

> WAFs block thousands of attacks a day. The SOC only needs to care about two questions: **did any attack get through, and did it work?**

## Triage decision tree
```mermaid
flowchart TD
  A[WAF / web attack alert] --> B{Were requests blocked?}
  B -- "Yes, all blocked" --> C{Targeted at a specific CVE<br/>of a product you run?}
  C -- No --> D[Background noise - block IP, close]
  C -- Yes --> E[Verify patch level, monitor]
  B -- "No - passed / detection mode" --> F{Response 200 with abnormal size,<br/>or 500 errors?}
  F -- Yes --> G[Possible success - check app/server logs<br/>see web shell playbook]
  F -- No --> H[Switch WAF policy to blocking<br/>monitor source]
```

## Investigation steps
1. Requests from the source: blocked vs passed, URLs, parameters, response codes and sizes.
   ```
   metadata.event_type = "NETWORK_HTTP" and principal.ip = "<SRC_IP>"
   ```
2. For passed requests: matching application/server logs and backend errors (SQL errors, stack traces).
3. For SSRF / Log4Shell: outbound connections from the web server to unknown hosts or the metadata endpoint.
4. Is the source a scanner (user agent, ASN) or targeted (low volume, precise payloads)?

## Containment & response
- Block the source IP/ASN at the WAF; virtual-patch the targeted CVE.
- Move policies from detection/transparent to blocking mode.
- If exploitation succeeded: isolate backend, rotate app secrets, run the web shell playbook.

## Escalation criteria
Any passed attack with evidence of success, or targeted exploitation of an unpatched CVE → IR.

## Evidence to collect
WAF logs (blocked + passed), backend logs, payload samples, source enrichment.
