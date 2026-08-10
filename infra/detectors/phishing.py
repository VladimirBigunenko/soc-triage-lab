"""PhishingAnalyzer — heuristics for phishing emails (MITRE T1566).

Checks authentication results (SPF/DKIM/DMARC) passed via structured
fields, plus content heuristics: mismatched Reply-To, brand-impersonation
domains, urgency keywords. A real .eml parser adapter can feed these
fields (Phase 5); the detector itself stays framework-agnostic.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import uuid4

from core.entities.alert import Alert, LogEvent
from core.entities.ioc import Ioc
from core.entities.severity import Severity

from infra.detectors.patterns import PHISHING_KEYWORDS

# Look-alike domains of common brands (typosquatting heuristics).
BRAND_DOMAINS: dict[str, str] = {
    "paypa1.com": "paypal.com",
    "paypal-secure.com": "paypal.com",
    "amaz0n.com": "amazon.com",
    "micros0ft.com": "microsoft.com",
    "appleid-help.com": "apple.com",
}


class PhishingAnalyzer:
    """Heuristic phishing detector based on email authentication + content."""

    name = "phishing"

    def analyze(self, event: LogEvent) -> Alert | None:
        if event.source != "email":
            return None

        reasons: list[str] = []

        spf = self._field(event, "spf", "email.auth.spf")
        dkim = self._field(event, "dkim", "email.auth.dkim")
        dmarc = self._field(event, "dmarc", "email.auth.dmarc")
        auth_fail = any(str(v).lower() in {"fail", "false"} for v in (spf, dkim, dmarc) if v is not None)
        if auth_fail:
            reasons.append("SPF/DKIM/DMARC authentication failed")

        sender = str(self._field(event, "from", "email.from.address") or "")
        reply_to = str(self._field(event, "reply_to", "email.reply_to.address") or "")
        if reply_to and sender and reply_to.lower() != sender.lower():
            reasons.append("Reply-To differs from From")

        domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
        for spoofed, legit in BRAND_DOMAINS.items():
            if domain == spoofed:
                reasons.append(f"Brand impersonation: {spoofed} (looks like {legit})")
                break

        subject = str(self._field(event, "subject", "email.subject") or "").lower()
        for keyword in PHISHING_KEYWORDS:
            if keyword in subject:
                reasons.append(f"Urgency/social-engineering keyword: '{keyword}'")
                break

        body = str(self._field(event, "body", "email.body.text") or "")
        links = re.findall(r"https?://([^\s'\">]+)", body)
        suspicious_links = [ln for ln in links if not any(b in ln.lower() for b in ["paypal.com", "amazon.com", "apple.com", "microsoft.com"])]
        if suspicious_links and ("login" in body.lower() or "verify" in body.lower()):
            reasons.append(f"Suspicious link with login/verify context: {suspicious_links[0]}")

        if not reasons:
            return None

        iocs: list[Ioc] = []
        sender_ip = self._field(event, "source_ip", "source.ip")
        if sender_ip:
            iocs.append(Ioc(type="ip", value=str(sender_ip), source=self.name, confidence=0.8))
        if domain:
            iocs.append(Ioc(type="domain", value=domain, source=self.name, confidence=0.8))
        for link in suspicious_links[:3]:
            host = link.split("/")[0]
            if host:
                iocs.append(Ioc(type="url", value=f"https://{host}", source=self.name, confidence=0.6))

        return Alert(
            id=f"ALT-{self.name}-{uuid4().hex[:8]}",
            detector=self.name,
            title="Suspected phishing email",
            severity=Severity.HIGH,
            source=event.source,
            timestamp=event.timestamp,
            description="; ".join(reasons),
            mitre="T1566",
            iocs=iocs,
            event=event,
            metadata={"reasons": reasons, "links": links},
        )

    @staticmethod
    def _field(event: LogEvent, *keys: str) -> Any:
        for key in keys:
            if key in event.fields:
                return event.fields[key]
        return None
