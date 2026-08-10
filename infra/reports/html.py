"""HtmlReportRenderer — incident report as a standalone HTML page."""

from __future__ import annotations

from html import escape

from core.entities.incident import Incident

from infra.reports.markdown import MarkdownReportRenderer


class HtmlReportRenderer:
    """Renders an incident into a minimal, dependency-free HTML page."""

    name = "html"

    def render_incident(self, incident: Incident) -> str:
        md = MarkdownReportRenderer().render_incident(incident)
        # Simple structured HTML built from incident data (kept tiny on purpose).
        rows = []

        for alert in incident.alerts:
            ioc_values = ", ".join(f"<code>{escape(i.value)}</code>" for i in alert.iocs)
            rows.append(
                "<li>"
                f"<strong>{escape(alert.severity.label)}</strong> — {escape(alert.title)} "
                f"<span class='muted'>({escape(alert.id)} · {escape(alert.detector)})</span>"
                + (f"<br>MITRE: {escape(alert.mitre)}" if alert.mitre else "")
                + (f"<br>IoCs: {ioc_values}" if ioc_values else "")
                + "</li>"
            )

        playbook_html = ""
        if incident.playbook is not None:
            steps = "".join(
                f"<li><strong>{s.order}.</strong> {escape(s.action)} "
                f"<span class='muted'>[{escape(s.assignee_role)}]</span></li>"
                for s in incident.playbook.steps
            )
            playbook_html = (
                f"<h2>Playbook: {escape(incident.playbook.name)}</h2><ol>{steps}</ol>"
            )

        ttps = ", ".join(escape(t) for t in sorted(incident.mitre_ttps)) or "n/a"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Incident {escape(incident.id)}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; color: #222; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: .3rem; }}
  .muted {{ color: #666; font-size: .9em; }}
  .badge {{ display: inline-block; padding: .1rem .5rem; border-radius: 4px; color: #fff; }}
  .Critical {{ background: #c0392b; }} .High {{ background: #e67e22; }}
  .Medium {{ background: #f1c40f; color:#333; }} .Low {{ background: #3498db; }} .Info {{ background: #95a5a6; }}
  li {{ margin-bottom: .4rem; }}
</style>
</head>
<body>
<h1>Incident {escape(incident.id)}</h1>
<p><span class="badge {escape(incident.severity.label)}">{escape(incident.severity.label)}</span>
 &nbsp; <strong>{escape(incident.title)}</strong></p>
<p class="muted">Status: {escape(incident.status.value)} · Alerts: {len(incident.alerts)} · MITRE TTPs: {ttps}</p>
<h2>Alerts</h2>
<ul>{''.join(rows)}</ul>
{playbook_html}
</body>
</html>
"""
