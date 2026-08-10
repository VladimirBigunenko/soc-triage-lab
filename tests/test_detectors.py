"""Tests for detectors (infra adapters)."""

from datetime import datetime, timedelta, timezone

from infra.detectors.brute_force import BruteForceDetector
from infra.detectors.phishing import PhishingAnalyzer
from infra.detectors.port_scan import PortScanDetector
from infra.detectors.sqli import SqlIDetector
from infra.detectors.ua_anomaly import UaAnomalyDetector
from infra.detectors.xss import XssDetector

from tests.conftest import make_event


def _at(minutes_ago: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)


class TestBruteForceDetector:
    def test_threshold_reached_fires_alert(self):
        detector = BruteForceDetector(window_minutes=10, threshold=3)
        for i in range(3):
            alert = detector.analyze(
                make_event(source="auth", fields={"ip": "1.2.3.4", "success": False}, timestamp=_at(i))
            )
        assert alert is not None
        assert alert.mitre == "T1110.001"
        assert alert.iocs[0].value == "1.2.3.4"
        assert alert.severity.value >= 3  # HIGH

    def test_below_threshold_no_alert(self):
        detector = BruteForceDetector(window_minutes=10, threshold=5)
        for i in range(3):
            detector.analyze(
                make_event(source="auth", fields={"ip": "1.2.3.4", "success": False}, timestamp=_at(i))
            )
        # third event returns None (never reached threshold)
        assert detector.analyze(
            make_event(source="auth", fields={"ip": "1.2.3.4", "success": False}, timestamp=_at(0))
        ) is None

    def test_success_resets_counter(self):
        detector = BruteForceDetector(window_minutes=10, threshold=3)
        for i in range(2):
            detector.analyze(
                make_event(source="auth", fields={"ip": "1.2.3.4", "success": False}, timestamp=_at(i + 1))
            )
        detector.analyze(
            make_event(source="auth", fields={"ip": "1.2.3.4", "success": True}, timestamp=_at(0))
        )
        assert detector.analyze(
            make_event(source="auth", fields={"ip": "1.2.3.4", "success": False}, timestamp=_at(0))
        ) is None

    def test_ignores_non_auth_source(self):
        detector = BruteForceDetector()
        assert detector.analyze(make_event(source="web", fields={"ip": "1.2.3.4"})) is None

    def test_ecs_field_names_supported(self):
        detector = BruteForceDetector(window_minutes=10, threshold=2)
        detector.analyze(
            make_event(
                source="auth",
                fields={"source.ip": "5.5.5.5", "event.outcome": "failure"},
                timestamp=_at(1),
            )
        )
        alert = detector.analyze(
            make_event(
                source="auth",
                fields={"source.ip": "5.5.5.5", "event.outcome": "failure"},
                timestamp=_at(0),
            )
        )
        assert alert is not None
        assert alert.iocs[0].value == "5.5.5.5"


class TestSqlIDetector:
    def test_detects_union_select(self):
        detector = SqlIDetector()
        alert = detector.analyze(make_event(source="web", fields={"url": "/search?q=1 UNION SELECT * FROM users"}))
        assert alert is not None
        assert alert.mitre == "T1190"

    def test_detects_boolean_injection(self):
        detector = SqlIDetector()
        alert = detector.analyze(make_event(source="web", fields={"url": "/login?id=1' OR '1'='1"}))
        assert alert is not None

    def test_detects_comment_trick(self):
        detector = SqlIDetector()
        alert = detector.analyze(make_event(source="web", fields={"url": "/user/1--"}))
        assert alert is not None

    def test_clean_url_no_alert(self):
        detector = SqlIDetector()
        assert detector.analyze(make_event(source="web", fields={"url": "/about?page=2"})) is None


class TestXssDetector:
    def test_detects_script_tag(self):
        detector = XssDetector()
        alert = detector.analyze(make_event(source="web", fields={"url": "/search?q=<script>alert(1)</script>"}))
        assert alert is not None
        assert alert.mitre == "T1059.007"

    def test_detects_onerror(self):
        detector = XssDetector()
        alert = detector.analyze(make_event(source="web", fields={"url": "/img?x=1 onerror=alert(1)"}))
        assert alert is not None

    def test_clean_no_alert(self):
        detector = XssDetector()
        assert detector.analyze(make_event(source="web", fields={"url": "/page"})) is None


class TestPortScanDetector:
    def test_many_distinct_ports_fire(self):
        detector = PortScanDetector(window_minutes=10, distinct_ports_threshold=5)
        alert = None
        for port in range(5):
            alert = detector.analyze(
                make_event(source="endpoint", fields={"ip": "9.9.9.9", "dst_port": 1000 + port}, timestamp=_at(port))
            )
        assert alert is not None
        assert alert.mitre == "T1046"
        assert alert.iocs[0].value == "9.9.9.9"

    def test_few_ports_no_alert(self):
        detector = PortScanDetector(window_minutes=10, distinct_ports_threshold=5)
        for port in range(3):
            detector.analyze(make_event(source="endpoint", fields={"ip": "9.9.9.9", "dst_port": 1000 + port}))
        assert detector.analyze(
            make_event(source="endpoint", fields={"ip": "9.9.9.9", "dst_port": 1999})
        ) is None

    def test_ignores_web_source(self):
        detector = PortScanDetector()
        assert detector.analyze(make_event(source="web", fields={"ip": "1.1.1.1", "dst_port": 80})) is None


class TestUaAnomalyDetector:
    def test_detects_sqlmap(self):
        detector = UaAnomalyDetector()
        alert = detector.analyze(make_event(source="web", fields={"user_agent": "sqlmap/1.7 (http://sqlmap.org)"}))
        assert alert is not None
        assert alert.mitre == "T1595"
        assert alert.metadata["matched_ua"] == "sqlmap"

    def test_detects_curl(self):
        detector = UaAnomalyDetector()
        assert detector.analyze(make_event(source="web", fields={"user_agent": "curl/8.0.1"})) is not None

    def test_normal_browser_no_alert(self):
        detector = UaAnomalyDetector()
        assert detector.analyze(make_event(source="web", fields={"user_agent": "Mozilla/5.0 (Windows NT 10.0)"})) is None


class TestPhishingAnalyzer:
    def test_auth_fail_detected(self):
        detector = PhishingAnalyzer()
        alert = detector.analyze(
            make_event(
                source="email",
                fields={
                    "from": "security@paypa1.com",
                    "subject": "Your account has been locked",
                    "spf": "fail",
                    "dkim": "fail",
                    "dmarc": "fail",
                },
            )
        )
        assert alert is not None
        assert alert.mitre == "T1566"
        assert alert.severity.value >= 3

    def test_brand_impersonation(self):
        detector = PhishingAnalyzer()
        alert = detector.analyze(
            make_event(
                source="email",
                fields={
                    "from": "support@paypa1.com",
                    "subject": "Confirm your password",
                    "spf": "pass",
                    "dkim": "pass",
                    "dmarc": "pass",
                },
            )
        )
        assert alert is not None
        assert any("Brand impersonation" in r for r in alert.metadata["reasons"])

    def test_reply_to_mismatch(self):
        detector = PhishingAnalyzer()
        alert = detector.analyze(
            make_event(
                source="email",
                fields={
                    "from": "ceo@company.com",
                    "reply_to": "attacker@evil.com",
                    "subject": "Bank transfer",
                },
            )
        )
        assert alert is not None
        assert any("Reply-To" in r for r in alert.metadata["reasons"])

    def test_legit_email_no_alert(self):
        detector = PhishingAnalyzer()
        assert detector.analyze(
            make_event(
                source="email",
                fields={
                    "from": "news@example.com",
                    "subject": "Weekly newsletter",
                    "spf": "pass",
                    "dkim": "pass",
                    "dmarc": "pass",
                },
            )
        ) is None
