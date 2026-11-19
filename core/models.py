"""
core/models.py - Data models for Security Misconfiguration Detector

Defines the Finding model (backward-compatible) and structured check-result
records used for transparent per-check reporting.
"""

from dataclasses import dataclass, asdict, field
from typing import Dict, Any, Optional

VALID_SEVERITIES = {"Info", "Low", "Medium", "High", "Critical"}
VALID_CONFIDENCES = {"Confirmed", "Likely"}
VALID_CHECK_STATUSES = {"PASS", "FAIL", "WARNING", "NOT TESTED"}

SCAN_MODE_PASSIVE_PUBLIC = "passive_public"
SCAN_MODE_AUTHORIZED_ASSESSMENT = "authorized_assessment"
VALID_SCAN_MODES = {SCAN_MODE_PASSIVE_PUBLIC, SCAN_MODE_AUTHORIZED_ASSESSMENT}
SCAN_MODE_LABELS = {
    SCAN_MODE_PASSIVE_PUBLIC: "Passive Public Inspection",
    SCAN_MODE_AUTHORIZED_ASSESSMENT: "Authorized Security Configuration Assessment",
}


@dataclass
class Finding:
    """
    Represents a single security misconfiguration finding.

    Attributes:
        id: Unique identifier for the finding (e.g., 'HDR-001')
        title: Short human-readable title describing the vulnerability
        category: Vulnerability category ('headers', 'cookies', 'paths', 'info_leaks')
        severity: Impact rating ('Info', 'Low', 'Medium', 'High', 'Critical')
        evidence: Concrete proof / observed response from the target
        fix: Actionable, step-by-step remediation advice
        confidence: Level of certainty ('Confirmed', 'Likely')
        url: Specific URL or endpoint where the issue was observed
    """
    id: str
    title: str
    category: str
    severity: str
    evidence: str
    fix: str
    confidence: str = "Confirmed"
    url: str = ""

    def __post_init__(self):
        # Normalize and validate severity
        canonical_sev = next((s for s in VALID_SEVERITIES if s.lower() == str(self.severity).strip().lower()), None)
        if not canonical_sev:
            raise ValueError(f"Invalid severity '{self.severity}'. Must be one of: {sorted(list(VALID_SEVERITIES))}")
        self.severity = canonical_sev

        # Normalize and validate confidence
        canonical_conf = next((c for c in VALID_CONFIDENCES if c.lower() == str(self.confidence).strip().lower()), None)
        if not canonical_conf:
            raise ValueError(f"Invalid confidence '{self.confidence}'. Must be one of: {sorted(list(VALID_CONFIDENCES))}")
        self.confidence = canonical_conf

    def to_dict(self) -> Dict[str, Any]:
        """Convert the Finding dataclass instance to a standard Python dictionary."""
        data = asdict(self)
        # Ensure required reporting fields are always present for JSON/report/dashboard consistency.
        data["remediation"] = self.fix

        description = str(getattr(self, "description", "") or "").strip()
        impact = str(getattr(self, "impact", "") or "").strip()

        if not description:
            description = str(self.title or "Security misconfiguration detected").strip()

        if not impact:
            sev = str(self.severity or "Info").upper()
            if sev in ("CRITICAL", "HIGH"):
                impact = "May significantly weaken security controls or expose sensitive data/capabilities if abused."
            elif sev == "MEDIUM":
                impact = "Can reduce defense-in-depth and increase exposure to client-side or server-side attacks."
            elif sev == "LOW":
                impact = "Represents a hardening gap that may aid reconnaissance or weaken protections in context."
            else:
                impact = "Informational observation with limited direct security impact based on available evidence."

        data["description"] = description
        data["impact"] = impact
        return data

    @property
    def remediation(self) -> str:
        """Backward-compatible alias for fix/remediation text."""
        return self.fix


@dataclass
class CheckResult:
    """
    Structured per-check/module result for transparent scan reporting.

    Status values:
      - PASS: Check executed and no issue was identified for this check scope.
      - FAIL: Check executed and identified evidenced misconfiguration(s).
      - WARNING: Check executed with cautionary observations or partial concerns.
      - NOT TESTED: Check could not be fully performed (connectivity, budget, cancellation, unsupported case).
    """
    name: str
    status: str
    severity: str = "Info"
    evidence: str = ""
    affected_url: str = ""
    explanation: str = ""
    remediation: str = ""
    category: str = "general"
    findings_count: int = 0

    def __post_init__(self):
        status = str(self.status or "").strip().upper().replace("_", " ")
        if status == "NOTTESTED":
            status = "NOT TESTED"
        if status not in VALID_CHECK_STATUSES:
            status = "NOT TESTED"
        self.status = status

        sev = str(self.severity or "Info").strip().title()
        if sev not in VALID_SEVERITIES:
            sev = "Info"
        self.severity = sev

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
