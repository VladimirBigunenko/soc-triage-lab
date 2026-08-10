# Incident Triage Scenario — Brute Force (T1110.001)

This document walks through a realistic L1 triage, the way an analyst at a
SOC would handle an alert from this project's pipeline. It demonstrates the
mindset the tooling encodes: **verify, decide, act, document**.

---

## 1. The alert arrives

From `scan_logs` (or `POST /api/scan`), the pipeline fires:

```text
[ALERT] High | Brute-force: 5 failed logins from 203.0.113.77 (MITRE: T1110.001)
```

Enriched metadata adds context:

```text
mitre_technique: Brute Force: Password Guessing
mitre_tactic:    Credential Access
mitre_guidance:  Correlate failed logins across hosts, look for the same
                 username, recommend account lockout policy review and MFA.
```

## 2. First look (what I check)

1. **Source IP** — is it a known scanner, VPN egress, or a legit customer IP?
   (Here: `203.0.113.77` — documentation range, i.e. attacker-like.)
2. **Target** — which account? (`admin` — a privileged account: raise attention.)
3. **Window** — how many failures in how long? (5 in 10 minutes — exceeds the
   threshold of the detector.)
4. **Outcome** — did any login *succeed* after the failures? The demo includes
   one success after the burst — that turns a "scan" into a **confirmed
   compromise attempt**.

## 3. Verification steps

- Correlate the same IP against other detectors (SQLi / XSS / UA anomaly):
  if the same IP appears in multiple techniques, the case becomes a campaign.
- Check the playbook attached by `PlaybookEngine`:

```text
Playbook: Brute Force Response (PB-BRUTE-FORCE)
0. Block source IP          [L1]
1. Verify affected accounts [L1]
2. Enable MFA               [L2]
3. Document and close       [L1]
```

## 4. Decision + escalation

| Finding | Decision |
|---------|----------|
| Failures only, no success, no other detectors | Resolve — monitor IP |
| Failures + **successful login** | **Escalate to L2** — account takeover response |
| Same IP in SQLi + XSS alerts | Escalate — multi-technique campaign |

In the demo, the escalation policy is encoded in `TriageService`:
CRITICAL/HIGH escalate, MEDIUM with IoCs escalates, LOW/INFO resolves.

## 5. Documentation

Every incident is rendered to a report — see
[`example-incident.md`](example-incident.md). The report is the deliverable:
it tells L2/L3 exactly what happened, what was checked, and what was done.

---

*This scenario mirrors the logic implemented in `core/services/triage.py` and
the playbooks in `infra/playbooks/library.py`.*
