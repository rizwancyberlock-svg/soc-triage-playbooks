---
id: PB-NET-001
title: DNS Tunneling, DGA and C2 Domains
severity: HIGH
mitre: T1071.004, T1568.002, T1048.003
related_rules: net_dns_tunneling_long_subdomain, net_dns_nxdomain_burst_dga, net_dns_to_external_resolver, umb_c2_or_malware_blocked, umb_newly_seen_domains_burst, fgt_botnet_c2_detected
---

# DNS Tunneling, DGA and C2 Domains

> DNS is allowed everywhere, so malware uses it to find C2 (DGA) and even to carry data (tunneling).

## Triage decision tree
```mermaid
flowchart TD
  A[Suspicious DNS] --> B{Domain belongs to a known<br/>security / CDN vendor?}
  B -- Yes --> C[Benign - allowlist domain, close]
  B -- No --> D{Pattern?}
  D -- "Long random subdomains, one parent domain" --> E[Tunneling - find the process]
  D -- "Many NXDOMAIN random names" --> F[DGA malware - find the process]
  D -- "Known C2 / malware category" --> G[Infected host - EDR triage]
  E --> H[Isolate host, block parent domain]
  F --> H
  G --> H
```

## Investigation steps
1. Group the queries by parent (registered) domain - tunneling uses one parent with thousands of unique subdomains.
2. Registration age and reputation of the parent domain (WHOIS, passive DNS).
3. Map the source IP to a hostname and find the process making the queries (EDR DNS telemetry / Sysmon EID 22).
4. Volume: bytes encoded in labels × query count ≈ data exfiltrated.

## Containment & response
- Block the parent domain at DNS security (Umbrella) and firewall.
- Isolate the host; triage the process with EDR.
- Force all DNS through corporate resolvers; block outbound 53/853 and known DoH endpoints elsewhere.

## Escalation criteria
Tunneling confirmed (possible exfiltration) or C2 from a server → IR.

## Evidence to collect
Query samples, parent domain intel, source host/process, estimated data volume.
