from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: EmailStr
    display_name: str
    role: str
    department: str
    active: bool
    demo_account: bool


class PatientSummary(BaseModel):
    id: str
    patient_reference: str
    display_name: str
    age_band: str
    department: str
    assigned_clinician: str
    access_allowed: bool


class PatientDetail(PatientSummary):
    synthetic: bool


class EventOut(BaseModel):
    id: str
    actor: str
    actor_role: str
    department: str
    action: str
    resource_reference: str
    timestamp: datetime
    authorization_result: str
    record_count: int
    destination_category: str | None
    risk_score: float
    severity: str
    signals: list[dict[str, Any]]
    explanation: str
    response_result: str
    ml_anomaly_score: float | None
    event_kind: str


class AlertOut(BaseModel):
    id: str
    event_id: str
    severity: str
    detected_at: datetime
    associated_user: str
    summary: str
    contributing_signals: list[dict[str, Any]]
    risk_score: float
    recommended_response: str
    status: str
    timeline: list[dict[str, Any]] = []


class ExportRequest(BaseModel):
    patient_ids: list[str] = Field(min_length=1, max_length=100)
    destination_category: str = Field(default="simulated-usb", pattern="^(simulated-usb|internal-report|approved-analytics)$")
    reason: str = Field(default="demo export", max_length=200)


class AlertActionRequest(BaseModel):
    note: str | None = Field(default=None, max_length=500)

