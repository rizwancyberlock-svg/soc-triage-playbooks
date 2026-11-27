# Contributing

New playbooks, better decision trees and real-world false-positive tips are all welcome.

1. Copy [`templates/playbook-template.md`](templates/playbook-template.md) into the right `playbooks/<area>/` folder.
2. Fill in the front matter:
   - `id`: `PB-<AREA>-<NNN>`, where AREA is `IDN` (identity), `EML` (email), `SAS` (SaaS / M365 data), `END` (endpoint), `CLD` (cloud), `AIS` (AI & agents), `NET` (network) or `DAT` (data security)
   - `severity`: `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`
   - `mitre`: ATT&CK technique IDs
   - `related_rules`: rule names from [open-yaral-detections](https://github.com/rizwancyberlock-svg/open-yaral-detections) (Google SecOps)
   - `related_kql` (optional): rule file names, without `.yaml`, from [sentinel-kql-detections](https://github.com/rizwancyberlock-svg/sentinel-kql-detections)
   - Every playbook needs detections in both libraries. Set `trigger: rule+hunt` when the playbook also ships hunting queries, or `trigger: hunt` only while a rule is being built. Both require at least one KQL hunting query.
   - ATT&CK technique IDs go in `mitre`. For AI attacks, MITRE ATLAS IDs (`AML.T…`) are also accepted.
3. Keep all required sections: When this fires, Triage decision tree (a Mermaid `flowchart`), Investigation steps, True vs false positive, Containment & response, Escalation criteria, Evidence to collect.
4. Write queries analysts can paste directly, using `<PLACEHOLDERS>` for values. Fence Sentinel queries as ```` ```kql ```` so CI compiles them. Use a plain fence for SecOps UDM searches.
5. Validate and regenerate the index:
   ```bash
   python tools/check_playbooks.py playbooks --index playbooks/INDEX.md \
     --rules-dir ../open-yaral-detections/rules --kql-dir ../sentinel-kql-detections/detections
   ```

Never include real customer data, hostnames, IPs or internal URLs.
