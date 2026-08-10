"""Tests for report renderers."""

from core.entities.incident import Incident
from core.entities.severity import Severity
from infra.reports.html import HtmlReportRenderer
from infra.reports.markdown import MarkdownReportRenderer

from tests.conftest import make_alert, make_ioc


def _incident() -> Incident:
    incident = Incident(id="INC-42", title="Brute force campaign", severity=Severity.HIGH)
    incident.add_alert(
        make_alert(
            title="Brute-force from 1.2.3.4",
            severity=Severity.HIGH,
            mitre="T1110.001",
            iocs=[make_ioc(value="1.2.3.4")],
        )
    )
    return incident


class TestMarkdownReportRenderer:
    def test_contains_core_sections(self):
        md = MarkdownReportRenderer().render_incident(_incident())
        assert "# Incident INC-42" in md
        assert "High" in md
        assert "T1110.001" in md
        assert "Brute-force from 1.2.3.4" in md
        assert "1.2.3.4" in md

    def test_playbook_section_when_attached(self):
        from core.services.playbooks import PlaybookEngine
        from infra.playbooks.library import PlaybookLibrary

        incident = _incident()
        PlaybookEngine(PlaybookLibrary()).apply(incident)
        md = MarkdownReportRenderer().render_incident(incident)
        assert "## Playbook" in md
        assert "Brute Force Response" in md


class TestHtmlReportRenderer:
    def test_is_html_document(self):
        html = HtmlReportRenderer().render_incident(_incident())
        assert html.startswith("<!DOCTYPE html>")
        assert "<h1>Incident INC-42</h1>" in html
        assert "Brute-force from 1.2.3.4" in html

    def test_escapes_user_content(self):
        incident = _incident()
        incident.title = 'Brute <script>alert(1)</script>'
        html = HtmlReportRenderer().render_incident(incident)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
