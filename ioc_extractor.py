"""
-------------------------
Extracts Indicators of Compromise from raw text using regex patterns.
Supports: IPv4, IPv6, domains, URLs, MD5/SHA1/SHA256 hashes, CVE IDs, emails.

Usage:
    from ioc_extractor import extract_iocs
    results = extract_iocs("Found malware calling back to 192.168.1.100 on CVE-2024-3400")
"""

import re
from collections import defaultdict


# ==============================================================================
# Regex Patterns
# ==============================================================================

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|info|biz|gov|mil|edu|co|us|uk|de|ru|cn|"
        r"xyz|top|cc|tk|pw|onion|bit|cloud|digital|online|site|tech|"
        r"app|dev|pro|me|in|br|fr|nl|se|au|ca|jp|kr|it|es|pl)\b"
    ),
    "url": re.compile(
        r"https?://[^\s<>\"')\]]+",
        re.IGNORECASE,
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    "mitre_technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
}

# Common false-positive IPs to filter out
PRIVATE_IP_RANGES = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.0\.0\.1|0\.0\.0\.0)"
)


# ==============================================================================
# Extraction Functions
# ==============================================================================

def extract_iocs(text, include_private_ips=False):
    """
    Extract all IOCs from a given text string.

    Args:
        text: Raw text to scan for IOCs.
        include_private_ips: If False (default), filters out RFC1918 addresses.

    Returns:
        Dict mapping IOC type -> list of unique IOC values found.
        Example: {"ipv4": ["1.2.3.4"], "cve": ["CVE-2024-3400"], ...}
    """
    results = defaultdict(list)

    # Handle defanged IOCs: 192[.]168[.]1[.]1, hxxp://, etc.
    defanged = text.replace("[.]", ".").replace("hxxp", "http").replace("hxxps", "https")

    for ioc_type, pattern in PATTERNS.items():
        matches = pattern.findall(defanged)
        unique = list(dict.fromkeys(matches))  # preserve order, deduplicate

        if ioc_type == "ipv4" and not include_private_ips:
            unique = [ip for ip in unique if not PRIVATE_IP_RANGES.match(ip)]

        # Filter hash false positives (too short patterns matching hex strings)
        if ioc_type == "md5":
            # Exclude sha1 and sha256 matches
            sha1_matches = set(PATTERNS["sha1"].findall(defanged))
            sha256_matches = set(PATTERNS["sha256"].findall(defanged))
            unique = [h for h in unique if h not in sha1_matches and h not in sha256_matches]

        if ioc_type == "sha1":
            sha256_matches = set(PATTERNS["sha256"].findall(defanged))
            unique = [h for h in unique if h not in sha256_matches]

        if unique:
            results[ioc_type] = unique

    return dict(results)


def format_iocs_for_display(iocs):
    """
    Format extracted IOCs into a readable string for display.

    Args:
        iocs: Dict from extract_iocs().

    Returns:
        Formatted string for Streamlit or console display.
    """
    if not iocs:
        return "No IOCs detected."

    lines = []
    type_labels = {
        "ipv4": "IPv4 Addresses",
        "ipv6": "IPv6 Addresses",
        "domain": "Domains",
        "url": "URLs",
        "md5": "MD5 Hashes",
        "sha1": "SHA1 Hashes",
        "sha256": "SHA256 Hashes",
        "cve": "CVE IDs",
        "email": "Email Addresses",
        "mitre_technique": "MITRE Technique IDs",
    }

    for ioc_type, values in iocs.items():
        label = type_labels.get(ioc_type, ioc_type.upper())
        lines.append(f"{label} ({len(values)}):")
        for v in values:
            lines.append(f"  - {v}")
        lines.append("")

    return "\n".join(lines)


def ioc_summary(iocs):
    """Return a one-line summary of IOC counts."""
    if not iocs:
        return "No IOCs found"
    parts = []
    for ioc_type, values in iocs.items():
        parts.append(f"{len(values)} {ioc_type}")
    return " | ".join(parts)
