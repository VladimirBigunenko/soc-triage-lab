# Incident INC-20260810121001-4013

- **Title:** Correlated: Suspected phishing email (https://paypa1-secure.example)
- **Severity:** High
- **Status:** investigating
- **Opened:** 2026-08-10T09:45:09.894665+00:00
- **Alerts:** 2
- **MITRE ATT&CK:** T1566

## Indicators of Compromise

| Type | Value | Confidence |
|------|-------|------------|
| ip | `91.240.118.40` | 0.80 |
| domain | `paypa1.com` | 0.80 |
| url | `https://paypa1-secure.example` | 0.60 |

## Playbook

**Phishing Response** (PB-PHISHING)

| # | Action | Role |
|---|--------|------|
| 0 | Confirm delivery | L1 |
| 1 | Block sender | L1 |
| 2 | Check credential exposure | L1 |
| 3 | Notify users | L2 |

## Alerts

- **[High]** Suspected phishing email (`ALT-phishing-65365387`) — phishing
  - MITRE: T1566
  - IoCs: `91.240.118.40`, `paypa1.com`, `https://paypa1-secure.example`
- **[High]** Suspected phishing email (`ALT-phishing-03dda117`) — phishing
  - MITRE: T1566
  - IoCs: `91.240.118.40`, `paypa1.com`, `https://paypa1-secure.example`

## Summary


[T1566] Phishing (Initial Access): Check if the email was delivered to other users (hunt), block the sender domain/IP, verify if credentials were entered, escalate to L2.
