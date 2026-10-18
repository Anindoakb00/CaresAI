from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(40), index=True)
    department: Mapped[str] = mapped_column(String(80), index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    demo_account: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SessionToken(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Patient(Base):
    __tablename__ = "patients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    patient_reference: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    first_name: Mapped[str] = mapped_column(String(80))
    last_name: Mapped[str] = mapped_column(String(80))
    age_band: Mapped[str] = mapped_column(String(20))
    department: Mapped[str] = mapped_column(String(80), index=True)
    assigned_clinician_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PatientAssignment(Base):
    __tablename__ = "patient_assignments"
    __table_args__ = (Index("ix_assignment_user_patient", "user_id", "patient_id", unique=True),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    patient_id: Mapped[str] = mapped_column(ForeignKey("patients.id", ondelete="CASCADE"), index=True)
    policy: Mapped[str] = mapped_column(String(60), default="care-team")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccessEvent(Base):
    __tablename__ = "access_events"
    __table_args__ = (
        Index("ix_event_timestamp", "event_timestamp"),
        Index("ix_event_actor_timestamp", "actor_id", "event_timestamp"),
        Index("ix_event_severity", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    actor_role: Mapped[str] = mapped_column(String(40))
    actor_department: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(50), index=True)
    resource_reference: Mapped[str] = mapped_column(String(80), index=True)
    patient_id: Mapped[str | None] = mapped_column(ForeignKey("patients.id"), nullable=True, index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    authorization_result: Mapped[str] = mapped_column(String(30), index=True)
    record_count: Mapped[int] = mapped_column(Integer, default=1)
    destination_category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    severity: Mapped[str] = mapped_column(String(20), default="low", index=True)
    detection_signals: Mapped[str] = mapped_column(Text, default="[]")
    explanation: Mapped[str] = mapped_column(Text, default="")
    response_result: Mapped[str] = mapped_column(String(80), default="logged")
    ml_anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    event_kind: Mapped[str] = mapped_column(String(40), default="access")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alert_status_severity", "status", "severity"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    event_id: Mapped[str] = mapped_column(ForeignKey("access_events.id"), index=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    summary: Mapped[str] = mapped_column(Text)
    contributing_signals: Mapped[str] = mapped_column(Text, default="[]")
    risk_score: Mapped[float] = mapped_column(Float)
    recommended_response: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IncidentAction(Base):
    __tablename__ = "incident_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(30))
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ModelMetadata(Base):
    __tablename__ = "model_metadata"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    version: Mapped[str] = mapped_column(String(80), unique=True)
    model_type: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(30))
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    evaluation_metrics: Mapped[str] = mapped_column(Text, default="{}")

