from collections import Counter


SEVERITY_SCORES = {
    "Low": 10,
    "Medium": 40,
    "High": 70,
    "Critical": 100
}


def _get_severity_score(severity):
    return SEVERITY_SCORES.get(
        severity,
        10
    )


def _get_threat_intelligence_score(
    ip,
    threat_intelligence
):
    """
    Calculate additional risk from external
    threat-intelligence providers.
    """

    if not ip:
        return 0

    for intelligence in threat_intelligence:

        if intelligence.get("ip") != ip:
            continue

        score = 0

        # VirusTotal
        virustotal = intelligence.get(
            "virustotal"
        ) or {}

        if virustotal.get("available"):

            malicious = virustotal.get(
                "malicious",
                0
            )

            suspicious = virustotal.get(
                "suspicious",
                0
            )

            if malicious > 0:
                score += 15

            elif suspicious > 0:
                score += 8

        # AbuseIPDB
        abuseipdb = intelligence.get(
            "abuseipdb"
        ) or {}

        if abuseipdb.get("available"):

            abuse_confidence = abuseipdb.get(
                "abuse_confidence_score",
                0
            )

            if abuse_confidence >= 75:
                score += 15

            elif abuse_confidence >= 50:
                score += 10

            elif abuse_confidence >= 25:
                score += 5

        return min(score, 30)

    return 0


def calculate_risk(
    findings,
    threat_intelligence=None
):
    """
    Calculate an explainable overall risk score.

    Factors:
    - Severity
    - Detection confidence
    - Attack frequency
    - Sensitive endpoint access
    - Threat intelligence
    """

    if not findings:
        return {
            "score": 0,
            "severity": "Low",
            "factors": {
                "severity": 0,
                "confidence": 0,
                "frequency": 0,
                "sensitive_endpoint": 0,
                "threat_intelligence": 0
            }
        }

    threat_intelligence = (
        threat_intelligence or []
    )

    # --------------------------------------------------------
    # Highest severity
    # --------------------------------------------------------

    severity_scores = [
        _get_severity_score(
            finding.get(
                "severity",
                "Low"
            )
        )
        for finding in findings
    ]

    highest_severity_score = max(
        severity_scores
    )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence_values = [
        finding.get(
            "confidence",
            0
        )
        for finding in findings
    ]

    average_confidence = (
        sum(confidence_values)
        / len(confidence_values)
    )

    confidence_bonus = round(
        average_confidence * 0.15
    )

    # --------------------------------------------------------
    # Attack frequency
    # --------------------------------------------------------

    attack_counts = Counter(
        finding.get(
            "attack",
            "Unknown"
        )
        for finding in findings
    )

    highest_frequency = max(
        attack_counts.values()
    )

    frequency_bonus = min(
        highest_frequency * 3,
        15
    )

    # --------------------------------------------------------
    # Sensitive endpoint
    # --------------------------------------------------------

    sensitive_endpoint_bonus = 0

    for finding in findings:

        if finding.get(
            "attack"
        ) == "Sensitive Endpoint Access":

            sensitive_endpoint_bonus = 5
            break

    # --------------------------------------------------------
    # Threat intelligence
    # --------------------------------------------------------

    threat_intelligence_bonus = 0

    processed_ips = set()

    for finding in findings:

        ip = finding.get("ip")

        if not ip or ip in processed_ips:
            continue

        processed_ips.add(ip)

        threat_intelligence_bonus += (
            _get_threat_intelligence_score(
                ip,
                threat_intelligence
            )
        )

    threat_intelligence_bonus = min(
        threat_intelligence_bonus,
        30
    )

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    score = (
        highest_severity_score
        + confidence_bonus
        + frequency_bonus
        + sensitive_endpoint_bonus
        + threat_intelligence_bonus
    )

    score = min(
        score,
        100
    )

    # --------------------------------------------------------
    # Overall severity
    # --------------------------------------------------------

    if score >= 90:
        severity = "Critical"

    elif score >= 70:
        severity = "High"

    elif score >= 40:
        severity = "Medium"

    else:
        severity = "Low"

    return {
        "score": score,
        "severity": severity,
        "factors": {
            "severity": highest_severity_score,
            "confidence": confidence_bonus,
            "frequency": frequency_bonus,
            "sensitive_endpoint": sensitive_endpoint_bonus,
            "threat_intelligence": threat_intelligence_bonus
        }
    }