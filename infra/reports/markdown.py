"""MarkdownReportRenderer — incident report as Markdown."""

from __future__ import annotations

from core.entities.incident import Incident


class MarkdownReportRenderer:
    """Renders an incident into a Markdown report suitable for docs/triage."""

    name = "markdown"

    def render_incident(self, incident: Incident) -> str:
        lines: list[str] = []
        lines.append(f"# Incident {incident.id}")
        lines.append("")
        lines.append(f"- **Title:** {incident.title}")
        lines.append(f"- **Severity:** {incident.severity.label}")
        lines.append(f"- **Status:** {incident.status.value}")
        lines.append(f"- **Opened:** {incident.opened_at.isoformat()}")
        lines.append(f"- **Alerts:** {len(incident.alerts)}")

        ttps = sorted(incident.mitre_ttps)
        if ttps:
            lines.append(f"- **MITRE ATT&CK:** {', '.join(ttps)}")

        iocs = incident.iocs
        if iocs:
            lines.append("")
            lines.append("## Indicators of Compromise")
            lines.append("")
            lines.append("| Type | Value | Confidence |")
            lines.append("|------|-------|------------|")
            for ioc in iocs:
                lines.append(f"| {ioc.type} | `{ioc.value}` | {ioc.confidence:.2f} |")

        if incident.playbook is not None:
            lines.append("")
            lines.append("## Playbook")
            lines.append("")
            lines.append(f"**{incident.playbook.name}** ({incident.playbook.id})")
            lines.append("")
            lines.append("| # | Action | Role |")
            lines.append("|---|--------|------|")
            for step in incident.playbook.steps:
                lines.append(f"| {step.order} | {step.action} | {step.assignee_role} |")

        lines.append("")
        lines.append("## Alerts")
        lines.append("")
        for alert in incident.alerts:
            lines.append(f"- **[{alert.severity.label}]** {alert.title} (`{alert.id}`) — {alert.detector}")
            if alert.mitre:
                lines.append(f"  - MITRE: {alert.mitre}")
            if alert.iocs:
                ioc_values = ", ".join(f"`{i.value}`" for i in alert.iocs)
                lines.append(f"  - IoCs: {ioc_values}")

        if incident.summary:
            lines.append("")
            lines.append("## Summary")
            lines.append("")
            lines.append(incident.summary)

        return "\n".join(lines) + "\n"
