import re


def analyze_log_line(line: str):
    line_lower = line.lower()

    # SQL Injection
    if any(pattern in line_lower for pattern in [
        "union select",
        "' or '1'='1",
        "select * from",
        "drop table",
    ]):
        return {
            "attack": "SQL Injection",
            "severity": "High",
            "risk_score": 90,
            "mitre_technique": "T1190",
            "reason": "Possible SQL injection pattern detected"
        }

    # Brute Force
    if any(pattern in line_lower for pattern in [
        "failed password",
        "authentication failure",
        "login failed",
        "invalid password",
    ]):
        return {
            "attack": "Brute Force",
            "severity": "Medium",
            "risk_score": 65,
            "mitre_technique": "T1110",
            "reason": "Authentication failure detected"
        }

    # Command Injection
    if any(pattern in line_lower for pattern in [
        "; whoami",
        "; id",
        "| whoami",
        "&& whoami",
        "/bin/bash",
    ]):
        return {
            "attack": "Command Injection",
            "severity": "Critical",
            "risk_score": 95,
            "mitre_technique": "T1059",
            "reason": "Possible command execution pattern detected"
        }

    # Directory Traversal
    if "../" in line or "..\\" in line:
        return {
            "attack": "Directory Traversal",
            "severity": "High",
            "risk_score": 85,
            "mitre_technique": "T1190",
            "reason": "Path traversal pattern detected"
        }

    # Suspicious scanning
    if any(pattern in line_lower for pattern in [
        "nmap",
        "port scan",
        "scan detected",
    ]):
        return {
            "attack": "Network Scanning",
            "severity": "Medium",
            "risk_score": 60,
            "mitre_technique": "T1046",
            "reason": "Possible network reconnaissance detected"
        }

    return None


def analyze_log(content: str):
    incidents = []

    for line_number, line in enumerate(
        content.splitlines(),
        start=1
    ):
        result = analyze_log_line(line)

        if result:
            incidents.append({
                "line_number": line_number,
                "raw_log": line.strip(),
                **result
            })

    return incidents