import re

from app.services.ioc_extractor import extract_iocs
from app.services.mitre_mapper import map_to_mitre


SQLI_PATTERNS = [
    r"union\s+select",
    r"or\s+1\s*=\s*1",
    r"information_schema",
    r"sleep\s*\(",
    r"benchmark\s*\(",
    r"drop\s+table",
    r"select\s+.*\s+from",
]


XSS_PATTERNS = [
    r"<script",
    r"</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"%3cscript",
]


DIRECTORY_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e",
]


SENSITIVE_PATHS = [
    "/admin",
    "/wp-admin",
    "/administrator",
    "/phpmyadmin",
    "/.git",
    "/.env",
    "/config",
]


SUSPICIOUS_USER_AGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "wpscan",
]


def detect_threats(logs):

    findings = []

    for log in logs:

        path = log.get("path", "")

        user_agent = log.get(
            "user_agent",
            ""
        )

        decoded = path.lower()

        attack = None
        severity = None

        # SQL Injection
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, decoded, re.IGNORECASE):
                attack = "SQL Injection"
                severity = "Critical"
                break

        # XSS
        if not attack:
            for pattern in XSS_PATTERNS:
                if re.search(pattern, decoded, re.IGNORECASE):
                    attack = "Cross Site Scripting"
                    severity = "High"
                    break

        # Directory Traversal
        if not attack:
            for pattern in DIRECTORY_TRAVERSAL_PATTERNS:
                if re.search(pattern, decoded, re.IGNORECASE):
                    attack = "Directory Traversal"
                    severity = "High"
                    break

        # Sensitive endpoint
        if not attack:
            for sensitive_path in SENSITIVE_PATHS:
                if sensitive_path in decoded:
                    attack = "Sensitive Endpoint Access"
                    severity = "Medium"
                    break

        # Suspicious scanner
        if not attack:
            for agent in SUSPICIOUS_USER_AGENTS:
                if agent in user_agent.lower():
                    attack = "Security Scanner Activity"
                    severity = "Medium"
                    break

        if attack:

            iocs = extract_iocs(log)

            mitre = map_to_mitre(attack)

            finding = {
                "ip": log.get("ip"),
                "timestamp": log.get("time"),
                "method": log.get("method"),
                "path": path,
                "status": log.get("status"),
                "attack": attack,
                "severity": severity,
                "iocs": iocs,
                "mitre": mitre
            }

            findings.append(finding)

    return findings