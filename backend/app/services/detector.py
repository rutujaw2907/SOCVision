import re
from collections import defaultdict

from app.services.ioc_extractor import extract_iocs
from app.services.mitre_mapper import map_to_mitre


# ============================================================
# ATTACK PATTERNS
# ============================================================

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
    r"%252e%252e",
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*(whoami|id|uname|ls|pwd|cat|curl|wget)",
    r"\|\s*(whoami|id|uname|ls|pwd|cat|curl|wget)",
    r"&&\s*(whoami|id|uname|ls|pwd|cat|curl|wget)",
    r"\$\([^)]*(whoami|id|uname|ls|pwd|cat|curl|wget)",
    r"`[^`]*(whoami|id|uname|ls|pwd|cat|curl|wget)",
    r"\b(cmd\.exe|powershell|bash|sh)\b",
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

ENUMERATION_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/server-status",
    "/server-info",
    "/backup",
    "/backup.zip",
    "/database",
    "/db",
    "/test",
    "/debug",
]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "wpscan",
    "dirbuster",
    "gobuster",
    "burpsuite",
    "burp",
    "acunetix",
]

AUTH_FAILURE_INDICATORS = [
    "401",
    "403",
    "failed password",
    "authentication failure",
    "login failed",
    "invalid password",
    "invalid credentials",
    "unauthorized",
]

AUTH_SUCCESS_INDICATORS = [
    "login successful",
    "authentication successful",
    "authenticated",
    "successful login",
]


# ============================================================
# HELPERS
# ============================================================

def _contains_pattern(value, patterns):
    value = value or ""

    for pattern in patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return pattern

    return None


def _is_auth_failure(log):
    status = str(log.get("status", ""))
    raw_log = str(log.get("raw_log", ""))

    message = f"{status} {raw_log}".lower()

    return any(
        indicator.lower() in message
        for indicator in AUTH_FAILURE_INDICATORS
    )


def _is_auth_success(log):
    status = str(log.get("status", ""))
    raw_log = str(log.get("raw_log", ""))

    message = f"{status} {raw_log}".lower()

    if status == "200":
        return True

    return any(
        indicator.lower() in message
        for indicator in AUTH_SUCCESS_INDICATORS
    )


def _base_finding(
    log,
    attack,
    severity,
    confidence,
    reason
):
    iocs = extract_iocs(log)
    mitre = map_to_mitre(attack)

    return {
        "ip": log.get("ip"),
        "timestamp": log.get("time"),
        "method": log.get("method"),
        "path": log.get("path"),
        "status": log.get("status"),
        "attack": attack,
        "severity": severity,
        "confidence": confidence,
        "reason": reason,
        "evidence": reason,
        "iocs": iocs,
        "mitre": mitre,
    }


# ============================================================
# MAIN DETECTOR
# ============================================================

def detect_threats(logs):

    findings = []

    # ========================================================
    # 1. Authentication statistics by IP
    # ========================================================

    failed_attempts = defaultdict(int)
    successful_attempts = defaultdict(int)

    first_failed_log = {}
    first_success_after_failure = {}

    for log in logs:

        ip = log.get("ip")

        if not ip:
            continue

        if _is_auth_failure(log):

            failed_attempts[ip] += 1

            if ip not in first_failed_log:
                first_failed_log[ip] = log

        if _is_auth_success(log):

            successful_attempts[ip] += 1

            if (
                failed_attempts.get(ip, 0) >= 3
                and ip not in first_success_after_failure
            ):
                first_success_after_failure[ip] = log

    # ========================================================
    # 2. Brute Force
    #
    # IMPORTANT:
    # Create ONE finding per source IP, not one finding
    # for every failed log line.
    # ========================================================

    for ip, failures in failed_attempts.items():

        if failures >= 5:

            severity = "High"

            confidence = min(
                70 + (failures * 5),
                98
            )

            reason = (
                f"{failures} authentication failures "
                f"detected from source IP {ip}"
            )

            finding = _base_finding(
                log=first_failed_log[ip],
                attack="Brute Force",
                severity=severity,
                confidence=confidence,
                reason=reason
            )

            findings.append(finding)

        elif failures >= 3:

            severity = "Medium"
            confidence = 75

            reason = (
                f"Multiple authentication failures "
                f"detected from source IP {ip}: "
                f"{failures} attempts"
            )

            finding = _base_finding(
                log=first_failed_log[ip],
                attack="Brute Force",
                severity=severity,
                confidence=confidence,
                reason=reason
            )

            findings.append(finding)

    # ========================================================
    # 3. Suspicious authentication success
    #
    # Separate from brute force.
    # ========================================================

    for ip, log in first_success_after_failure.items():

        failures = failed_attempts.get(ip, 0)

        finding = _base_finding(
            log=log,
            attack="Suspicious Authentication Success",
            severity="High",
            confidence=85,
            reason=(
                f"Successful authentication observed "
                f"after {failures} failed attempts "
                f"from the same source IP"
            )
        )

        findings.append(finding)

    # ========================================================
    # 4. Analyze individual web/security events
    # ========================================================

    for log in logs:

        path = str(
            log.get("path", "")
        )

        user_agent = str(
            log.get("user_agent", "")
        )

        decoded = path.lower()

        attack = None
        severity = None
        confidence = 0
        reason = ""

        # ----------------------------------------------------
        # SQL Injection
        # ----------------------------------------------------

        matched_pattern = _contains_pattern(
            decoded,
            SQLI_PATTERNS
        )

        if matched_pattern:

            attack = "SQL Injection"
            severity = "Critical"
            confidence = 95

            reason = (
                f"SQL injection pattern detected: "
                f"{matched_pattern}"
            )

        # ----------------------------------------------------
        # Command Injection
        # ----------------------------------------------------

        if not attack:

            matched_pattern = _contains_pattern(
                decoded,
                COMMAND_INJECTION_PATTERNS
            )

            if matched_pattern:

                attack = "Command Injection"
                severity = "Critical"
                confidence = 95

                reason = (
                    f"Command injection pattern detected: "
                    f"{matched_pattern}"
                )

        # ----------------------------------------------------
        # XSS
        # ----------------------------------------------------

        if not attack:

            matched_pattern = _contains_pattern(
                decoded,
                XSS_PATTERNS
            )

            if matched_pattern:

                attack = "Cross Site Scripting"
                severity = "High"
                confidence = 90

                reason = (
                    f"Cross-site scripting pattern detected: "
                    f"{matched_pattern}"
                )

        # ----------------------------------------------------
        # Directory Traversal
        # ----------------------------------------------------

        if not attack:

            matched_pattern = _contains_pattern(
                decoded,
                DIRECTORY_TRAVERSAL_PATTERNS
            )

            if matched_pattern:

                attack = "Directory Traversal"
                severity = "High"
                confidence = 92

                reason = (
                    f"Directory traversal pattern detected: "
                    f"{matched_pattern}"
                )

        # ----------------------------------------------------
        # Sensitive Endpoint Access
        # ----------------------------------------------------

        if not attack:

            for sensitive_path in SENSITIVE_PATHS:

                if sensitive_path in decoded:

                    attack = "Sensitive Endpoint Access"
                    severity = "Medium"
                    confidence = 80

                    reason = (
                        f"Access to sensitive endpoint "
                        f"detected: {sensitive_path}"
                    )

                    break

        # ----------------------------------------------------
        # Directory Enumeration
        # ----------------------------------------------------

        if not attack:

            for enumeration_path in ENUMERATION_PATHS:

                if enumeration_path in decoded:

                    attack = "Directory Enumeration"
                    severity = "Medium"
                    confidence = 75

                    reason = (
                        f"Potential directory or resource "
                        f"enumeration detected: "
                        f"{enumeration_path}"
                    )

                    break

        # ----------------------------------------------------
        # Security Scanner Activity
        # ----------------------------------------------------

        if not attack:

            for agent in SUSPICIOUS_USER_AGENTS:

                if agent in user_agent.lower():

                    attack = "Security Scanner Activity"
                    severity = "Medium"
                    confidence = 90

                    reason = (
                        f"Known security scanning tool "
                        f"detected in User-Agent: {agent}"
                    )

                    break

        # ----------------------------------------------------
        # Save web/security finding
        # ----------------------------------------------------

        if attack:

            finding = _base_finding(
                log=log,
                attack=attack,
                severity=severity,
                confidence=confidence,
                reason=reason
            )

            findings.append(finding)

    return findings