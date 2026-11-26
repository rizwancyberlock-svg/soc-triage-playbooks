---
id: PB-CLD-003
title: Cloud Storage Exposure and Snapshot Sharing
severity: HIGH
mitre: T1530, T1537
related_rules: aws_s3_public_access_block_removed, aws_s3_bucket_policy_changed, aws_snapshot_or_ami_shared, gcp_bucket_iam_changed, m365_anonymous_link_created, m365_mass_file_download
---

# Cloud Storage Exposure and Snapshot Sharing

> Buckets made public and snapshots shared to foreign accounts are how cloud data leaves without a single network alert.

## Triage decision tree
```mermaid
flowchart TD
  A[Storage exposure change] --> B{Bucket/link is meant to be public?<br/>website, public dataset}
  B -- Yes --> C[Benign - document owner, close]
  B -- No --> D{Contains sensitive data?<br/>check tags / DSPM / names}
  D -- Yes --> E[Revert immediately, check access logs<br/>possible breach]
  D -- No --> F[Revert, notify owner]
  A --> G{Snapshot shared to account<br/>outside your organization?}
  G -- Yes --> E
```

## Investigation steps
1. What exactly changed: public access block removed, policy with `"Principal": "*"`, ACL `AllUsers`, `allUsers` IAM member, snapshot `createVolumePermission` with an external account ID.
2. Who did it, from where, and what else did they do?
3. Was data accessed after exposure? S3 server access logs / CloudTrail data events / GCS data access logs for anonymous or foreign-account reads.
4. Data classification of the resource.

## Containment & response
- Re-enable Block Public Access / remove public members / revoke the snapshot share.
- Enable account-level Block Public Access and org policies (`storage.publicAccessPrevention`).
- If data was accessed: engage privacy/legal for breach assessment.

## Escalation criteria
Sensitive data + external access, or snapshot shared to unknown account → IR + privacy.

## Evidence to collect
Policy before/after, access logs, external account IDs, data classification.
