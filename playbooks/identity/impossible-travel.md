---
id: PB-IDN-004
title: Impossible Travel / Multi-Country Logins
severity: MEDIUM
mitre: T1078, T1078.004
related_rules: auth_login_multiple_countries, entra_high_risk_signin
related_kql: entra-sign-in-multiple-countries, entra-new-country-sign-in, entra-high-risk-user
---

# Impossible Travel / Multi-Country Logins

> Successful logins for one account from several countries in a short window. Most are VPNs - the job is to find the one that isn't.

## When this fires
- `auth_login_multiple_countries` - successful logins from 3+ countries within 1h
- `entra_high_risk_signin` - Entra ID Protection flagged a successful sign-in as high risk
- `entra-sign-in-multiple-countries` (Sentinel): One account signs in successfully from three or more countries within an hour
- `entra-new-country-sign-in` (Sentinel): A successful sign-in from a country the account has not signed in from in the previous 14 days
- `entra-high-risk-user` (Sentinel): Any ID Protection risk detection rated high (leaked credentials, password spray, unfamiliar features, malicious IP...)

## Triage decision tree
```mermaid
flowchart TD
  A[Multi-country login] --> B{Are the IPs corporate VPN,<br/>proxy or mobile carrier?}
  B -- Yes --> C[Benign - add egress ranges to exclusion, close]
  B -- No --> D{Same device / user agent<br/>across countries?}
  D -- Yes --> E[Likely personal VPN<br/>confirm with user]
  D -- No --> F{Token or session reuse?<br/>no interactive MFA from 2nd country}
  F -- Yes --> G[Session hijack / AiTM phishing<br/>Containment]
  F -- No --> H[Confirm with user, monitor]
```

## Investigation steps
1. List the countries, IPs, ASNs and user agents (`$countries` outcome).
2. Check whether the second location completed MFA or reused a session/refresh token - token reuse without MFA suggests **adversary-in-the-middle (AiTM) phishing** (Evilginx, Tycoon).
3. Search the user's mailbox for a recent phishing email leading to a fake login page.
4. Review activity from the suspicious location: mail access, file downloads, consent grants.

## True vs false positive

| Points to attack | Points to benign |
|---|---|
| Second location is a hosting / VPS ASN and the session token is new | Corporate VPN or SASE egress in another country |
| Same user agent missing from the user's history | User travelling, confirmed by the travel system or manager |
| Followed by mailbox rules, MFA changes or consent grants | Mobile carrier IP geolocated to a neighbouring country |

## Containment & response
- Revoke sessions and refresh tokens (password reset alone does **not** kill stolen session cookies).
- Reset password, review MFA methods and inbox rules.
- Block the attacker IP / ASN in Conditional Access; consider token protection and compliant-device requirements.

## Escalation criteria
Session reuse without MFA, mailbox/file access from the suspicious country, or privileged users → IR.

## Evidence to collect
Sign-in records (IPs, ASNs, UAs, session IDs), phishing email (if any), post-access activity.
