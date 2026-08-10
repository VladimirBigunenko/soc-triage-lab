"""MITRE ATT&CK adapter — built-in knowledge base.

A focused subset of techniques relevant to a SOC L1 portfolio. Each
entry carries ``l1_guidance`` — practical actions for the analyst.
In a production deployment this could be replaced by an API-backed
repository; the domain only depends on the TechniqueRepository port.
"""

from __future__ import annotations

from core.entities.mitre import Technique

MITRE_BASE: dict[str, Technique] = {
    "T1110": Technique(
        id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        description="Adversaries may use brute force to gain access to accounts when passwords are unknown.",
        l1_guidance="Verify source IP reputation, check for successful logins after the failures, consider blocking the IP and enforcing MFA.",
    ),
    "T1110.001": Technique(
        id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic="Credential Access",
        description="Adversaries attempt a small number of password guesses against a single account without triggering lockouts.",
        l1_guidance="Correlate failed logins across hosts, look for the same username, recommend account lockout policy review and MFA enforcement.",
    ),
    "T1190": Technique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Adversaries exploit a weakness in an Internet-facing system to gain initial access.",
        l1_guidance="Identify the affected application, check for recent CVEs, collect the request payload for forensics, escalate to L2 with WAF review.",
    ),
    "T1059.007": Technique(
        id="T1059.007",
        name="Command and Scripting Interpreter: JavaScript",
        tactic="Execution",
        description="Adversaries may abuse JavaScript interpreters to execute code, including reflected/stored XSS payloads.",
        l1_guidance="Sanitize the payload, check whether the script executed (browser/UA logs), advise input validation and Content-Security-Policy.",
    ),
    "T1046": Technique(
        id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        description="Adversaries scan the network to discover services running on remote systems.",
        l1_guidance="Confirm scan origin, check for follow-up exploitation attempts, block the scanning source, review exposed services.",
    ),
    "T1566": Technique(
        id="T1566",
        name="Phishing",
        tactic="Initial Access",
        description="Adversaries send phishing messages to gain access to victim systems.",
        l1_guidance="Check if the email was delivered to other users (hunt), block the sender domain/IP, verify if credentials were entered, escalate to L2.",
    ),
    "T1595": Technique(
        id="T1595",
        name="Active Scanning",
        tactic="Reconnaissance",
        description="Adversaries actively scan victim infrastructure to gather information.",
        l1_guidance="Log the scanner source, monitor for repeat scans, consider perimeter rules; low priority unless paired with exploitation.",
    ),
    "T1071.001": Technique(
        id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        description="Adversaries communicate using application-layer protocols such as HTTP/HTTPS.",
        l1_guidance="Check frequency/regularity of beaconing, correlate with suspicious UAs, escalate to L2 for C2 analysis.",
    ),
    "T1189": Technique(
        id="T1189",
        name="Drive-by Compromise",
        tactic="Initial Access",
        description="Adversaries gain access through a user visiting a compromised website.",
        l1_guidance="Identify the visited page, check browser/AV logs for payload drops, isolate affected endpoints.",
    ),
    "T1059": Technique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversaries abuse command and script interpreters to execute commands.",
        l1_guidance="Correlate process-creation logs, identify the executed command, isolate the host if the command is malicious.",
    ),
}


class MitreAttckRepository:
    """TechniqueRepository implementation backed by the built-in base."""

    name = "mitre-attck-builtin"

    def get(self, technique_id: str) -> Technique | None:
        return MITRE_BASE.get(technique_id)

    def list_all(self) -> list[Technique]:
        return list(MITRE_BASE.values())


__all__ = ["MITRE_BASE", "MitreAttckRepository"]
