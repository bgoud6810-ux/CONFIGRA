"""
core/scoring.py - Security scoring and letter grade calculation

Calculates numeric score (0-100) and letter grade (A-F) based on finding
severities and confidence ratings.
"""

from typing import List, Tuple, Any

SEVERITY_PENALTIES = {
    "CRITICAL": 25.0,
    "HIGH": 15.0,
    "MEDIUM": 8.0,
    "LOW": 3.0,
    "INFO": 0.0,
}


def score_and_grade(findings: List[Any]) -> Tuple[int, str]:
    """
    Calculate the overall security score and letter grade from a list of findings.

    Scoring rules:
      - Starts at 100
      - Penalty per finding:
          * Critical: -25
          * High: -15
          * Medium: -8
          * Low: -3
          * Info: -0
      - 'Likely' confidence findings count for half penalty (50%)
      - Minimum score is 0
      - Grade scale:
          * A: 90 - 100
          * B: 75 - 89
          * C: 60 - 74
          * D: 40 - 59
          * F: 0 - 39

    Returns:
        (score, grade) e.g., (62, 'C')
    """
    total_penalty = 0.0

    for finding in findings:
        # Access attributes or dict keys
        if isinstance(finding, dict):
            sev = str(finding.get("severity", "Info")).upper()
            conf = str(finding.get("confidence", "Confirmed")).upper()
        else:
            sev = str(getattr(finding, "severity", "Info")).upper()
            conf = str(getattr(finding, "confidence", "Confirmed")).upper()

        base_penalty = SEVERITY_PENALTIES.get(sev, 0.0)

        # Halve penalty if confidence is Likely
        if conf == "LIKELY":
            base_penalty *= 0.5

        total_penalty += base_penalty

    # Compute final score clamped to [0, 100]
    final_score = max(0, int(round(100.0 - total_penalty)))

    # Determine letter grade
    if final_score >= 90:
        grade = "A"
    elif final_score >= 75:
        grade = "B"
    elif final_score >= 60:
        grade = "C"
    elif final_score >= 40:
        grade = "D"
    else:
        grade = "F"

    return final_score, grade
