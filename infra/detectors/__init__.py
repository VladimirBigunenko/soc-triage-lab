"""Detectors — export all adapters."""

from infra.detectors.brute_force import BruteForceDetector
from infra.detectors.phishing import PhishingAnalyzer
from infra.detectors.port_scan import PortScanDetector
from infra.detectors.sqli import SqlIDetector
from infra.detectors.ua_anomaly import UaAnomalyDetector
from infra.detectors.xss import XssDetector

DEFAULT_DETECTORS = (
    BruteForceDetector(),
    SqlIDetector(),
    XssDetector(),
    PortScanDetector(),
    PhishingAnalyzer(),
    UaAnomalyDetector(),
)

__all__ = [
    "BruteForceDetector",
    "SqlIDetector",
    "XssDetector",
    "PortScanDetector",
    "PhishingAnalyzer",
    "UaAnomalyDetector",
    "DEFAULT_DETECTORS",
]
