"""Detection patterns and constants shared by detectors.

Central place for signatures — keeps detectors readable and allows
easy tuning (add a UA, extend a regex) without touching logic.
"""

from __future__ import annotations

import re

# --- SQL injection signatures (case-insensitive) ---
SQLI_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(\bunion\b\s+\bselect\b)", re.I),
    re.compile(r"(select\s+.+\s+from\s+.+)", re.I),
    re.compile(r"(sleep\s*\(\s*\d+)", re.I),
    re.compile(r"(waitfor\s+delay)", re.I),
    re.compile(r"('|\")\s*(or|and)\s*('|\")?", re.I),
    re.compile(r"(--|#|/\*)", re.I),
    re.compile(r"(0x[0-9a-fA-F]{6,})", re.I),
    re.compile(r"(information_schema)", re.I),
)

# --- XSS signatures ---
XSS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<script[^>]*>", re.I),
    re.compile(r"(javascript\s*:)", re.I),
    re.compile(r"(onerror\s*=)", re.I),
    re.compile(r"(onload\s*=)", re.I),
    re.compile(r"(onclick\s*=)", re.I),
    re.compile(r"(alert\s*\(\s*['\"])", re.I),
    re.compile(r"(prompt\s*\(\s*['\"])", re.I),
    re.compile(r"(confirm\s*\(\s*['\"])", re.I),
    re.compile(r"<img[^>]*src\s*=", re.I),
)

# --- Known scanner / offensive tool User-Agents (lowercased) ---
SUSPICIOUS_USER_AGENTS: frozenset[str] = frozenset(
    {
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "zgrab",
        "nessus",
        "acunetix",
        "burpsuite",
        "dirbuster",
        "hydra",
        "gobuster",
        "wpscan",
        "fimap",
        "havij",
        "python-requests",
        "python-urllib",
        "curl",
        "wget",
        "libwww-perl",
    }
)

# --- Phishing heuristics ---
PHISHING_KEYWORDS: tuple[str, ...] = (
    "verify your account",
    "account suspended",
    "unusual sign-in",
    "confirm your password",
    "update payment",
    "bank transfer",
    "login verification",
    "your account has been locked",
)
