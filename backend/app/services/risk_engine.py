SEVERITY_SCORES = {
    "Low": 10,
    "Medium": 40,
    "High": 70,
    "Critical": 100
}


def calculate_risk(findings):
    """
    Calculate an overall risk score from detected findings.
    """

    if not findings:
        return {
            "score": 0,
            "severity": "Low"
        }

    scores = [
        SEVERITY_SCORES.get(
            finding.get("severity", "Low"),
            10
        )
        for finding in findings
    ]

    highest_score = max(scores)

    if highest_score >= 90:
        severity = "Critical"
    elif highest_score >= 70:
        severity = "High"
    elif highest_score >= 40:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "score": highest_score,
        "severity": severity
    }