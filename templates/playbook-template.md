---
id: PB-XXX-000
title: Playbook Title
severity: HIGH
mitre: T0000
related_rules: rule_name_one, rule_name_two
---

# Playbook Title

> One or two sentences: what is happening and the single question that matters most.

## Triage decision tree
```mermaid
flowchart TD
  A[Alert] --> B{Key question?}
  B -- Yes --> C[Action]
  B -- No --> D[Action]
```

## Investigation steps
1. Step with a UDM search query:
   ```
   principal.hostname = "<HOST>"
   ```

## Containment & response
- Action

## Escalation criteria
When to escalate and to whom.

## Evidence to collect
What to preserve.
