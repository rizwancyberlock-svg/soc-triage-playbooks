# Contributing

New playbooks, better decision trees and real-world false-positive tips are all welcome.

1. Copy [`templates/playbook-template.md`](templates/playbook-template.md) into the right `playbooks/<area>/` folder.
2. Fill in the front matter:
   - `id`: `PB-<AREA>-<NNN>`, where AREA is `IDN`, `END`, `CLD`, `NET` or `DAT`
   - `severity`: `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`
   - `mitre`: technique IDs
   - `related_rules`: rule names from [open-yaral-detections](https://github.com/rizwancyberlock-svg/open-yaral-detections)
3. Keep all required sections. The decision tree must be a Mermaid `flowchart`.
4. Write queries that analysts can paste directly, using `<PLACEHOLDERS>` for values.
5. Validate and regenerate the index:
   ```bash
   python tools/check_playbooks.py playbooks --index playbooks/INDEX.md --rules-dir ../open-yaral-detections/rules
   ```

Never include real customer data, hostnames, IPs or internal URLs.
