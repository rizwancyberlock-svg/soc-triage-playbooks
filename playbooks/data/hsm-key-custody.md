---
id: PB-DAT-004
title: HSM / Key Management Attack (Thales Luna, CipherTrust)
severity: CRITICAL
mitre: T1110.001, T1552.004, T1485, T1562.002
related_rules: hsm_luna_repeated_login_failures, hsm_luna_key_wrap_export, hsm_luna_partition_created_or_deleted, hsm_luna_audit_config_changed, hsm_luna_zeroize_or_factory_reset, ctm_admin_login_failures, ctm_key_destroyed_or_exported, ctm_logging_disabled
related_kql: azure-keyvault-deleted-or-purged, aws-kms-key-deletion
---

# HSM / Key Management Attack (Thales Luna, CipherTrust)

> HSM incidents are rare but catastrophic: stolen signing / TLS / payment keys enable undetectable impersonation, and destroyed keys mean permanently unreadable data.

## When this fires
- `hsm_luna_repeated_login_failures` (SecOps): Five or more failed Crypto Officer / partition login attempts against a Thales Luna HSM from the same client within 10 minutes
- `hsm_luna_key_wrap_export` (SecOps): 10+ key wrap / export / clone operations from one client within an hour - key material leaving the HSM boundary
- `hsm_luna_partition_created_or_deleted` (SecOps): Luna HSM partition created, deleted, initialized or cleared - deleting a partition destroys its keys irreversibly
- `hsm_luna_audit_config_changed` (SecOps): Luna HSM audit configuration changed or audit logging disabled
- `hsm_luna_zeroize_or_factory_reset` (SecOps): HSM zeroize, factory reset or re-initialization - destroys ALL key material on the appliance
- `ctm_admin_login_failures` (SecOps): Five or more failed CipherTrust Manager logins from one source within 15 minutes
- `ctm_key_destroyed_or_exported` (SecOps): Keys destroyed, deleted, revoked or exported in CipherTrust Manager
- `ctm_logging_disabled` (SecOps): Syslog / audit log forwarding deleted or disabled on CipherTrust Manager
- `azure-keyvault-deleted-or-purged` (Sentinel): Deleting or purging a Key Vault destroys keys (and everything encrypted with them); access-policy changes grant someone read access to every secret
- `aws-kms-key-deletion` (Sentinel): ScheduleKeyDeletion / DisableKey

## Triage decision tree
```mermaid
flowchart TD
  A[HSM / KMS alert] --> B{Which pattern?}
  B -- "Login failures" --> C{Client is a known app server<br/>after a recent deployment?}
  C -- Yes --> D[Wrong partition PIN - fix before lockout<br/>notify app owner]
  C -- No --> E[Unknown client - block NTLS access<br/>investigate host]
  B -- "Key wrap / export / clone" --> F{Scheduled backup to<br/>known backup HSM?}
  F -- Yes --> G[Benign - close]
  F -- No --> H[CRITICAL - key material may be exposed]
  B -- "Partition delete / zeroize / audit off" --> I{Approved change with<br/>dual control evidence?}
  I -- Yes --> G
  I -- No --> H
```

## Investigation steps
1. Identify the client (NTLS client cert / IP), role used (Security Officer, Crypto Officer, Crypto User), partition and key labels/handles.
2. Check the HSM change calendar and **M-of-N / dual-control** records - legitimate destructive operations require them.
3. For key export: which keys, wrapping key used, destination. Was the key marked extractable? (`CKA_EXTRACTABLE`).
4. Review the client host for compromise (EDR alerts, logins).
5. Confirm audit logs are still flowing - attackers disable HSM audit first.

## True vs false positive

| Points to attack | Points to benign |
|---|---|
| Key export or wrap to an unknown target outside a ceremony | Documented key ceremony with dual control and witnesses |
| Repeated partition / Security Officer login failures from a new host | Operator mistyping during a scheduled maintenance |
| Audit logging disabled before the key operation | Firmware upgrade procedure that temporarily changes audit config |

## Containment & response
- Revoke the client's NTLS registration / partition assignment; change partition credentials.
- If private keys may be exposed: revoke and re-issue the affected certificates, rotate data keys, notify PKI and payment teams.
- If keys were destroyed: restore from backup HSM per key recovery procedure.
- Restore audit configuration and syslog forwarding.

## Escalation criteria
Any unexplained export, deletion, zeroize or audit change → IR + crypto custodian + CISO.

## Evidence to collect
HSM audit log (signed audit records), client details, key handles/labels, change and dual-control records.
