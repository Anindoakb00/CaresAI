from dataclasses import dataclass
from typing import Any


SEVERITY_BANDS = ((24, "low"), (49, "medium"), (79, "high"), (100, "critical"))


@dataclass
class RiskAssessment:
    score: float
    severity: str
    signals: list[dict[str, Any]]
    explanation: str
    recommendation: str


def severity_for(score: float) -> str:
    for upper, label in SEVERITY_BANDS:
        if score <= upper:
            return label
    return "critical"


def assess_risk(
    *,
    action: str,
    authorized: bool,
    record_count: int = 1,
    department_mismatch: bool = False,
    repeated_unrelated: bool = False,
    denied_attempts: int = 0,
    unusual_time: bool = False,
    destination_category: str | None = None,
    ml_anomaly_score: float | None = None,
) -> RiskAssessment:
    """Deterministic, capped risk assessment over metadata only.

    Primary signal weights intentionally mirror the demo story. Secondary signals
    add bounded context, and each named signal is added at most once.
    """
    if not authorized and action == "export":
        score = 95.0
        signal = {"code": "unauthorized_export", "label": "Unauthorized protected-data export", "weight": 95, "explanation": "The requested export destination is not approved for this account."}
        signals = [signal]
        explanation = "Critical-risk activity detected because a protected export was requested for an unauthorized destination."
        return RiskAssessment(score, "critical", signals, explanation, "Deny export and notify security analyst")

    signals: list[dict[str, Any]] = []
    score = 5.0

    if repeated_unrelated:
        score = max(score, 65.0)
        signals.append({"code": "repeated_unrelated_access", "label": "Repeated access to unrelated records", "weight": 65, "explanation": "The account touched records outside its expected care context in a short window."})
    if record_count >= 25:
        score = max(score, 65.0 if repeated_unrelated else 55.0)
        signals.append({"code": "high_volume", "label": "Unusually high access volume", "weight": 55, "explanation": f"{record_count} synthetic records were requested in one activity sequence."})
    if action in {"bulk-download", "bulk_access"} or record_count >= 50:
        score = max(score, 85.0)
        signals.append({"code": "bulk_download", "label": "Bulk-download attempt", "weight": 85, "explanation": "A bulk operation can move many records at once and requires review."})
    if department_mismatch:
        score = max(score, 35.0)
        signals.append({"code": "department_mismatch", "label": "Unusual department access", "weight": 35, "explanation": "The activity does not match the actor's configured department context."})
    if denied_attempts > 0:
        score = min(100.0, score + min(15.0, denied_attempts * 5.0))
        signals.append({"code": "denied_attempt", "label": "Denied access attempt", "weight": 15, "explanation": f"{denied_attempts} authorization check(s) were denied."})
    if unusual_time:
        score = min(100.0, score + 10.0)
        signals.append({"code": "unusual_time", "label": "Unusual access timing", "weight": 10, "explanation": "The activity occurred outside the configured demo business window."})
    if ml_anomaly_score is not None and ml_anomaly_score >= 70:
        score = min(100.0, score + 10.0)
        signals.append({"code": "ml_anomaly", "label": "ML anomaly signal", "weight": 10, "explanation": f"The metadata pattern received an anomaly score of {ml_anomaly_score:.0f}/100."})

    score = round(max(0.0, min(100.0, score)), 1)
    severity = severity_for(score)
    if score >= 80:
        recommendation = "Notify security analyst and temporarily restrict the relevant operation"
    elif score >= 50:
        recommendation = "Review activity and notify security analyst"
    elif score >= 25:
        recommendation = "Review activity"
    else:
        recommendation = "Allow and log"
    if signals:
        labels = ", ".join(s["label"].lower() for s in signals[:2])
        explanation = f"{severity.title()}-risk activity detected because of {labels}."
    else:
        explanation = "Authorized synthetic record access matched the actor's configured care context."
    return RiskAssessment(score, severity, signals, explanation, recommendation)

