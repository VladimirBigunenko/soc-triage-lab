"""Built-in playbook library — response procedures keyed by MITRE technique."""

from __future__ import annotations

from core.entities.playbook import Playbook, PlaybookStep

PLAYBOOKS: dict[str, Playbook] = {
    "T1110.001": Playbook(
        id="PB-BRUTE-FORCE",
        name="Brute Force Response",
        trigger="T1110.001",
        steps=(
            PlaybookStep(0, "Block source IP", "Temporarily block the offending IP at the perimeter/firewall.", "L1"),
            PlaybookStep(1, "Verify affected accounts", "Check for successful logins after failures; force password reset.", "L1"),
            PlaybookStep(2, "Enable MFA", "Require MFA for the targeted accounts.", "L2"),
            PlaybookStep(3, "Document and close", "Record findings in the incident report.", "L1"),
        ),
    ),
    "T1110": Playbook(
        id="PB-BRUTE-FORCE-GENERIC",
        name="Brute Force Response",
        trigger="T1110",
        steps=(
            PlaybookStep(0, "Isolate source", "Block the source IP or account lockout policy check.", "L1"),
            PlaybookStep(1, "Correlate", "Look for the same username/host across other alerts.", "L1"),
            PlaybookStep(2, "Escalate if persistent", "Hand over to L2 for deeper analysis.", "L1"),
        ),
    ),
    "T1059.007": Playbook(
        id="PB-XSS",
        name="Cross-Site Scripting Response",
        trigger="T1059.007",
        steps=(
            PlaybookStep(0, "Sanitize the payload", "Capture the full payload for analysis; confirm if it executed.", "L1"),
            PlaybookStep(1, "Check for execution", "Review browser/UA and server logs for script execution.", "L1"),
            PlaybookStep(2, "Advise hardening", "Recommend input validation, output encoding and Content-Security-Policy.", "L2"),
            PlaybookStep(3, "Document", "Record the finding and affected endpoints.", "L1"),
        ),
    ),
    "T1566": Playbook(
        id="PB-PHISHING",
        name="Phishing Response",
        trigger="T1566",
        steps=(
            PlaybookStep(0, "Confirm delivery", "Check if the email reached other mailboxes (hunt).", "L1"),
            PlaybookStep(1, "Block sender", "Block sender domain/IP and quarantine the message.", "L1"),
            PlaybookStep(2, "Check credential exposure", "Verify if any user submitted credentials.", "L1"),
            PlaybookStep(3, "Notify users", "Inform affected users; advise password reset if needed.", "L2"),
        ),
    ),
    "T1190": Playbook(
        id="PB-EXPLOIT-PUBLIC",
        name="Exploit Public-Facing Application",
        trigger="T1190",
        steps=(
            PlaybookStep(0, "Identify the application", "Pinpoint which service was targeted.", "L1"),
            PlaybookStep(1, "Collect the payload", "Save the request payload for forensics.", "L1"),
            PlaybookStep(2, "Check for CVEs", "Correlate with known vulnerabilities; patch if confirmed.", "L2"),
            PlaybookStep(3, "Escalate", "Hand over to L2 with WAF review.", "L1"),
        ),
    ),
    "T1046": Playbook(
        id="PB-PORT-SCAN",
        name="Port Scan Response",
        trigger="T1046",
        steps=(
            PlaybookStep(0, "Confirm the scan", "Verify distinct ports/sources in the window.", "L1"),
            PlaybookStep(1, "Monitor for follow-up", "Watch for exploitation attempts after the scan.", "L1"),
            PlaybookStep(2, "Review exposure", "Recommend closing unnecessary open ports.", "L2"),
        ),
    ),
    "T1595": Playbook(
        id="PB-SCANNING",
        name="Active Scanning",
        trigger="T1595",
        steps=(
            PlaybookStep(0, "Log the scanner", "Record source IP and scanner signature.", "L1"),
            PlaybookStep(1, "Monitor for repeat", "Watch for recurring scans; block if persistent.", "L1"),
            PlaybookStep(2, "Close as informational", "Low priority unless paired with exploitation.", "L1"),
        ),
    ),
}


class PlaybookLibrary:
    """PlaybookRepository adapter backed by the built-in library."""

    name = "playbook-builtin"

    def get_by_technique(self, technique_id: str) -> Playbook | None:
        return PLAYBOOKS.get(technique_id)

    def list_all(self) -> list[Playbook]:
        return list(PLAYBOOKS.values())


__all__ = ["PLAYBOOKS", "PlaybookLibrary"]
