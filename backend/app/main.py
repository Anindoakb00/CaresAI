import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db, init_db
from .ml import get_detector, get_granite_engine
from .models import AccessEvent, Alert, IncidentAction, Patient, PatientAssignment, User
from .risk import assess_risk, severity_for
from .schemas import AlertActionRequest, AlertOut, EventOut, ExportRequest, LoginRequest, PatientDetail, PatientSummary, UserOut
from .security import create_session, current_user, delete_session, issue_csrf_token, require_csrf, require_roles, verify_password
from .seed import seed_demo

settings = get_settings()
app = FastAPI(title="CareShield AI API", version="0.1.0", description="Synthetic patient privacy monitoring prototype")
app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
_failed_login_attempts: dict[str, list[float]] = {}


@app.on_event("startup")
def startup() -> None:
    if settings.environment == "production" and (not os.getenv("SECRET_KEY") or settings.secret_key == "local-demo-secret-change-me" or len(settings.secret_key) < 32):
        raise RuntimeError("Production mode requires a unique SECRET_KEY with at least 32 characters")
    init_db()
    if settings.seed_demo_data:
        from .db import SessionLocal

        with SessionLocal() as db:
            seed_demo(db)


def _set_auth_cookies(response: Response, session: str) -> None:
    secure = settings.environment == "production"
    response.set_cookie("careshield_session", session, httponly=True, secure=secure, samesite="lax", max_age=settings.session_ttl_hours * 3600)
    response.set_cookie("careshield_csrf", issue_csrf_token(), httponly=False, secure=secure, samesite="lax", max_age=settings.session_ttl_hours * 3600)


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("careshield_session")
    response.delete_cookie("careshield_csrf")


def _user_name(db: Session, user_id: str) -> str:
    user = db.get(User, user_id)
    return user.display_name if user else "Unknown actor"


def _record_failed_login(db: Session, user: User | None) -> None:
    assessment = assess_risk(action="login", authorized=False, denied_attempts=1, unusual_time=False)
    db.add(AccessEvent(actor_id=user.id if user else None, actor_role=user.role if user else "unknown", actor_department=user.department if user else "authentication", action="login", resource_reference="auth:login", event_timestamp=datetime.now(timezone.utc), authorization_result="denied", record_count=0, risk_score=assessment.score, severity=assessment.severity, detection_signals=json.dumps(assessment.signals), explanation="A login attempt failed authentication; no credential details were stored.", response_result="rejected", event_kind="authentication", ml_anomaly_score=None))
    db.commit()


def _event_out(db: Session, event: AccessEvent) -> EventOut:
    return EventOut(id=event.id, actor=_user_name(db, event.actor_id), actor_role=event.actor_role, department=event.actor_department, action=event.action, resource_reference=event.resource_reference, timestamp=event.event_timestamp, authorization_result=event.authorization_result, record_count=event.record_count, destination_category=event.destination_category, risk_score=event.risk_score, severity=event.severity, signals=json.loads(event.detection_signals or "[]"), explanation=event.explanation, response_result=event.response_result, ml_anomaly_score=event.ml_anomaly_score, event_kind=event.event_kind)


def _alert_out(db: Session, alert: Alert) -> AlertOut:
    actions = list(db.scalars(select(IncidentAction).where(IncidentAction.alert_id == alert.id).order_by(IncidentAction.created_at)).all())
    timeline = [{"action": action.action, "actor": _user_name(db, action.actor_id), "note": action.note, "timestamp": action.created_at} for action in actions]
    return AlertOut(id=alert.id, event_id=alert.event_id, severity=alert.severity, detected_at=alert.detected_at, associated_user=_user_name(db, alert.actor_id), summary=alert.summary, contributing_signals=json.loads(alert.contributing_signals or "[]"), risk_score=alert.risk_score, recommended_response=alert.recommended_response, status=alert.status, timeline=timeline)


def _authorized_patient(db: Session, user: User, patient_id: str) -> Patient:
    patient = db.get(Patient, patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Synthetic patient not found")
    if user.role == "administrator":
        # Administration does not imply clinical record access.
        raise HTTPException(status_code=403, detail="Clinical record permission required")
    assignment = db.scalar(select(PatientAssignment).where(PatientAssignment.user_id == user.id, PatientAssignment.patient_id == patient.id))
    if not assignment:
        raise HTTPException(status_code=403, detail="Patient is outside your assigned care context")
    return patient


def _make_event(
    db: Session,
    actor: User,
    *,
    action: str,
    resource_reference: str,
    patient_id: str | None,
    authorized: bool,
    record_count: int = 1,
    destination_category: str | None = None,
    department_mismatch: bool = False,
    repeated_unrelated: bool = False,
    denied_attempts: int = 0,
    unusual_time: bool | None = None,
    event_kind: str = "access",
    response_result: str = "logged",
) -> AccessEvent:
    detector = get_detector()
    now = datetime.now(timezone.utc)
    if unusual_time is None:
        unusual_time = now.hour < 6 or now.hour > 22
    features = {
        "record_count": record_count,
        "frequency_window": record_count,
        "denied_attempts": denied_attempts,
        "department_mismatch": int(department_mismatch),
        "unusual_time": int(unusual_time),
        "bulk_operation": int(record_count >= 25 or action == "bulk-download"),
        "unauthorized_export": int(action == "export" and not authorized),
    }
    ml_score = detector.infer(features)
    assessment = assess_risk(
        action=action,
        authorized=authorized,
        record_count=record_count,
        department_mismatch=department_mismatch,
        repeated_unrelated=repeated_unrelated,
        denied_attempts=denied_attempts,
        unusual_time=bool(features["unusual_time"]),
        destination_category=destination_category,
        ml_anomaly_score=ml_score,
    )
    event = AccessEvent(
        actor_id=actor.id,
        actor_role=actor.role,
        actor_department=actor.department,
        action=action,
        resource_reference=resource_reference,
        patient_id=patient_id,
        authorization_result="allowed" if authorized else "denied",
        record_count=record_count,
        destination_category=destination_category,
        risk_score=assessment.score,
        severity=assessment.severity,
        detection_signals=json.dumps(assessment.signals),
        explanation=assessment.explanation,
        response_result=response_result,
        ml_anomaly_score=ml_score,
        event_kind=event_kind,
    )
    db.add(event)
    db.flush()
    if assessment.score >= 50:
        granite_engine = get_granite_engine()
        granite_reasoning = granite_engine.explain_alert(
            actor_role=actor.role,
            department=actor.department,
            action=action,
            record_count=record_count,
            risk_score=assessment.score,
            signals=assessment.signals,
        )
        alert = Alert(
            event_id=event.id,
            actor_id=actor.id,
            severity=assessment.severity,
            summary=granite_reasoning,
            contributing_signals=json.dumps(assessment.signals),
            risk_score=assessment.score,
            recommended_response=assessment.recommendation,
        )
        db.add(alert)
    return event


@app.get("/api/health")
def health(db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        db.execute(select(func.count(User.id)))
        db_status = "healthy"
    except Exception:
        db_status = "unavailable"
    return {
        "status": "ok" if db_status == "healthy" else "degraded",
        "database": db_status,
        "environment": settings.environment,
        "application_version": "0.1.0",
        "ibm_target": {
            "configured": True,
            "platform": "IBM LinuxONE Community Cloud (s390x)",
            "hardware_acceleration": "IBM Telum AI-Ready Architecture",
            "status": "live-l1cc-deployment",
        },
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> dict[str, Any]:
    client_key = request.client.host if request.client else "unknown"
    now = time.monotonic()
    attempts = [stamp for stamp in _failed_login_attempts.get(client_key, []) if now - stamp < 60]
    if len(attempts) >= 5:
        raise HTTPException(status_code=429, detail="Too many login attempts; try again shortly")
    user = db.scalar(select(User).where(User.email == str(payload.email).lower()))
    if not user or not verify_password(payload.password, user.password_hash):
        attempts.append(now)
        _failed_login_attempts[client_key] = attempts
        _record_failed_login(db, user)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    _failed_login_attempts.pop(client_key, None)
    token = create_session(db, user)
    _set_auth_cookies(response, token)
    return {"user": UserOut.model_validate(user), "message": "Signed in"}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db), user: User = Depends(require_csrf)) -> dict[str, str]:
    delete_session(db, request.cookies.get("careshield_session"))
    _clear_auth_cookies(response)
    return {"message": "Signed out"}


@app.get("/api/auth/me")
def me(user: User = Depends(current_user)) -> UserOut:
    return UserOut.model_validate(user)


@app.get("/api/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict[str, Any]:
    total = db.scalar(select(func.count(AccessEvent.id))) or 0
    authorized = db.scalar(select(func.count(AccessEvent.id)).where(AccessEvent.authorization_result == "allowed")) or 0
    denied = db.scalar(select(func.count(AccessEvent.id)).where(AccessEvent.authorization_result == "denied")) or 0
    suspicious = db.scalar(select(func.count(AccessEvent.id)).where(AccessEvent.risk_score >= 50)) or 0
    high = db.scalar(select(func.count(Alert.id)).where(Alert.severity == "high")) or 0
    critical = db.scalar(select(func.count(Alert.id)).where(Alert.severity == "critical")) or 0
    open_incidents = db.scalar(select(func.count(Alert.id)).where(Alert.status != "resolved")) or 0
    buckets = {label: db.scalar(select(func.count(AccessEvent.id)).where(AccessEvent.severity == label)) or 0 for label in ("low", "medium", "high", "critical")}
    signals: dict[str, int] = {}
    for event in db.scalars(select(AccessEvent)).all():
        for signal in json.loads(event.detection_signals or "[]"):
            signals[signal["label"]] = signals.get(signal["label"], 0) + 1
    common = sorted(([{"label": k, "count": v} for k, v in signals.items()]), key=lambda x: x["count"], reverse=True)[:5]
    return {"total_events": total, "authorized_accesses": authorized, "denied_attempts": denied, "suspicious_events": suspicious, "high_alerts": high, "critical_alerts": critical, "open_incidents": open_incidents, "risk_distribution": buckets, "common_signals": common, "demo_data": True}


@app.get("/api/dashboard/timeline")
def dashboard_timeline(db: Session = Depends(get_db), user: User = Depends(current_user)) -> list[dict[str, Any]]:
    events = list(db.scalars(select(AccessEvent).order_by(AccessEvent.event_timestamp.desc()).limit(30)).all())
    return [{"timestamp": e.event_timestamp, "allowed": 1 if e.authorization_result == "allowed" else 0, "denied": 1 if e.authorization_result == "denied" else 0, "risk": e.risk_score} for e in reversed(events)]


@app.get("/api/events")
def list_events(page: int = Query(1, ge=1), page_size: int = Query(12, ge=1, le=100), severity: str | None = None, action: str | None = None, user_id: str | None = None, date_from: str | None = None, date_to: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_roles("administrator", "security_analyst"))) -> dict[str, Any]:
    query = select(AccessEvent).order_by(AccessEvent.event_timestamp.desc())
    if severity:
        query = query.where(AccessEvent.severity == severity)
    if action:
        query = query.where(AccessEvent.action == action)
    if user_id:
        query = query.where(AccessEvent.actor_id == user_id)
    try:
        if date_from:
            query = query.where(AccessEvent.event_timestamp >= datetime.fromisoformat(f"{date_from}T00:00:00+00:00"))
        if date_to:
            query = query.where(AccessEvent.event_timestamp < datetime.fromisoformat(f"{date_to}T00:00:00+00:00") + timedelta(days=1))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Dates must use YYYY-MM-DD format") from exc
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    events = list(db.scalars(query.offset((page - 1) * page_size).limit(page_size)).all())
    return {"items": [_event_out(db, e) for e in events], "page": page, "page_size": page_size, "total": total, "pages": max(1, (total + page_size - 1) // page_size)}


@app.get("/api/events/{event_id}")
def get_event(event_id: str, db: Session = Depends(get_db), user: User = Depends(require_roles("administrator", "security_analyst"))) -> EventOut:
    event = db.get(AccessEvent, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return _event_out(db, event)


@app.get("/api/alerts")
def list_alerts(status_filter: str | None = Query(None, alias="status"), severity: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_roles("administrator", "security_analyst"))) -> list[AlertOut]:
    query = select(Alert).order_by(Alert.detected_at.desc())
    if status_filter:
        query = query.where(Alert.status == status_filter)
    if severity:
        query = query.where(Alert.severity == severity)
    return [_alert_out(db, a) for a in db.scalars(query.limit(100)).all()]


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db), user: User = Depends(require_roles("administrator", "security_analyst"))) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_out(db, alert)


def _change_alert(alert_id: str, action: str, payload: AlertActionRequest, db: Session, user: User) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if action == "acknowledge" and alert.status == "open":
        alert.status = "acknowledged"
    elif action == "resolve":
        alert.status = "resolved"
    db.add(IncidentAction(alert_id=alert.id, actor_id=user.id, action=action, note=payload.note))
    db.commit()
    db.refresh(alert)
    return _alert_out(db, alert)


@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str, payload: AlertActionRequest, db: Session = Depends(get_db), user: User = Depends(require_csrf)) -> AlertOut:
    if user.role not in {"administrator", "security_analyst"}:
        raise HTTPException(status_code=403, detail="Incident response permission required")
    return _change_alert(alert_id, "acknowledge", payload, db, user)


@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: str, payload: AlertActionRequest, db: Session = Depends(get_db), user: User = Depends(require_csrf)) -> AlertOut:
    if user.role not in {"administrator", "security_analyst"}:
        raise HTTPException(status_code=403, detail="Incident response permission required")
    return _change_alert(alert_id, "resolve", payload, db, user)


@app.get("/api/patients")
def list_patients(db: Session = Depends(get_db), user: User = Depends(current_user)) -> list[PatientSummary]:
    assignments = list(db.scalars(select(PatientAssignment).where(PatientAssignment.user_id == user.id)).all())
    patients = [db.get(Patient, a.patient_id) for a in assignments]
    if user.role == "security_analyst":
        # Analysts see only minimized directory metadata.
        patients = list(db.scalars(select(Patient).limit(50)).all())
    return [PatientSummary(id=p.id, patient_reference=p.patient_reference, display_name=f"{p.first_name[0]}. {p.last_name}", age_band=p.age_band, department=p.department, assigned_clinician=_user_name(db, p.assigned_clinician_id), access_allowed=user.role != "security_analyst" and any(a.patient_id == p.id for a in assignments)) for p in patients if p]


@app.get("/api/patients/{patient_id}")
def get_patient(patient_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)) -> PatientDetail:
    patient = _authorized_patient(db, user, patient_id)
    event = _make_event(db, user, action="view", resource_reference=patient.patient_reference, patient_id=patient.id, authorized=True, unusual_time=False, response_result="allowed")
    db.commit()
    return PatientDetail(id=patient.id, patient_reference=patient.patient_reference, display_name=f"{patient.first_name} {patient.last_name}", age_band=patient.age_band, department=patient.department, assigned_clinician=_user_name(db, patient.assigned_clinician_id), access_allowed=True, synthetic=patient.synthetic)


@app.get("/api/patients/{patient_id}/access-history")
def patient_history(patient_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)) -> list[EventOut]:
    _authorized_patient(db, user, patient_id)
    events = list(db.scalars(select(AccessEvent).where(AccessEvent.patient_id == patient_id).order_by(AccessEvent.event_timestamp.desc()).limit(50)).all())
    return [_event_out(db, e) for e in events]


@app.get("/api/users")
def list_users(db: Session = Depends(get_db), user: User = Depends(require_roles("administrator", "security_analyst"))) -> list[UserOut]:
    return [UserOut.model_validate(u) for u in db.scalars(select(User).order_by(User.display_name)).all()]


@app.get("/api/roles")
def roles(user: User = Depends(current_user)) -> list[dict[str, Any]]:
    return [{"role": "administrator", "permissions": ["system settings", "user management", "incident response"]}, {"role": "doctor", "permissions": ["assigned synthetic patient records", "record access audit"]}, {"role": "nurse", "permissions": ["assigned care-team records", "record access audit"]}, {"role": "security_analyst", "permissions": ["minimized patient directory", "events", "alerts", "incident response"]}]


@app.post("/api/exports/request")
def request_export(payload: ExportRequest, db: Session = Depends(get_db), user: User = Depends(require_csrf)) -> dict[str, Any]:
    authorized = payload.destination_category in {"internal-report", "approved-analytics"} and user.role in {"administrator", "security_analyst"}
    if payload.destination_category == "simulated-usb":
        authorized = False
    event = _make_event(db, user, action="export", resource_reference=f"export:{len(payload.patient_ids)}-records", patient_id=None, authorized=authorized, record_count=len(payload.patient_ids), destination_category=payload.destination_category, event_kind="export", response_result="exported" if authorized else "blocked")
    db.commit()
    alert = db.scalar(select(Alert).where(Alert.event_id == event.id))
    return {"allowed": authorized, "event_id": event.id, "alert_id": alert.id if alert else None, "risk_score": event.risk_score, "severity": event.severity, "reason": event.explanation, "response": event.response_result, "export_payload": None if not authorized else {"record_count": len(payload.patient_ids), "destination_category": payload.destination_category}}


@app.get("/api/model/status")
def model_status(user: User = Depends(current_user)) -> dict[str, Any]:
    payload = get_detector().status_payload()
    granite = get_granite_engine()
    payload["generative_ai"] = {
        "model": granite.model_id,
        "framework": granite.framework,
        "status": granite.status,
        "role": "LLM Reasoning and Explainable Alert Synthesis",
    }
    payload["ai_frameworks_count"] = 2
    payload["active_frameworks"] = ["scikit-learn (IsolationForest)", "huggingface_hub (IBM Granite 3.0)"]
    return payload


@app.post("/api/demo/normal-access")
def demo_normal(db: Session = Depends(get_db), user: User = Depends(require_csrf)) -> dict[str, Any]:
    doctor = db.scalar(select(User).where(User.email == "doctor@careshield.demo"))
    patient = db.scalar(select(Patient).where(Patient.patient_reference == "SYN-1001"))
    if user.role not in {"administrator", "doctor", "nurse"} or not doctor or not patient:
        raise HTTPException(status_code=403, detail="Demo scenario requires a clinical demo context")
    # Use the signed-in actor where possible, while keeping the flow repeatable.
    event = _make_event(db, user, action="view", resource_reference=patient.patient_reference, patient_id=patient.id, authorized=True, unusual_time=False, response_result="allowed")
    db.commit()
    return {"scenario": "normal-access", "message": "Authorized synthetic record access logged", "event": _event_out(db, event)}


@app.post("/api/demo/suspicious-access")
def demo_suspicious(db: Session = Depends(get_db), user: User = Depends(require_csrf)) -> dict[str, Any]:
    if user.role not in {"administrator", "security_analyst"}:
        raise HTTPException(status_code=403, detail="Demo scenario requires analyst permission")
    actor = db.scalar(select(User).where(User.email == "doctor@careshield.demo")) or user
    patients = list(db.scalars(select(Patient).limit(6)).all())
    last_event = None
    for patient in patients:
        last_event = _make_event(db, actor, action="bulk_access", resource_reference=patient.patient_reference, patient_id=patient.id, authorized=False, record_count=48, department_mismatch=True, repeated_unrelated=True, denied_attempts=1, event_kind="access", response_result="restricted")
    db.commit()
    alert = db.scalar(select(Alert).where(Alert.event_id == last_event.id)) if last_event else None
    return {"scenario": "suspicious-access", "message": "Deterministic mass-access sequence recorded and escalated", "event": _event_out(db, last_event), "alert": _alert_out(db, alert) if alert else None}


@app.post("/api/demo/unauthorized-export")
def demo_export(db: Session = Depends(get_db), user: User = Depends(require_csrf)) -> dict[str, Any]:
    payload = ExportRequest(patient_ids=["SYN-1001", "SYN-1002", "SYN-1003"], destination_category="simulated-usb", reason="demo")
    return request_export(payload, db, user)


@app.post("/api/demo/reset")
def demo_reset(db: Session = Depends(get_db), user: User = Depends(require_csrf)) -> dict[str, str]:
    if user.role != "administrator":
        raise HTTPException(status_code=403, detail="Administrator permission required")
    # Preserve users, assignments, and application configuration; reset only demo telemetry.
    db.query(IncidentAction).delete()
    db.query(Alert).delete()
    db.query(AccessEvent).delete()
    db.commit()
    seed_demo(db)
    return {"message": "Demo telemetry reset; user accounts and configuration were preserved"}


@app.get("/api/system/status")
def system_status(db: Session = Depends(get_db), user: User = Depends(current_user)) -> dict[str, Any]:
    health_result = health(db)
    return {
        "application_version": "0.1.0",
        "environment": settings.environment,
        "mode": "live-linuxone",
        "api": "healthy",
        "database": health_result["database"],
        "models": {
            "predictive": get_detector().status,
            "generative": get_granite_engine().status,
        },
        "ibm_target": health_result["ibm_target"],
        "architecture": [
            "React + TypeScript frontend",
            "FastAPI + SQLAlchemy backend",
            "Predictive AI: scikit-learn IsolationForest metadata anomaly detector",
            "Generative AI: IBM Granite 3.0 LLM explainable risk reasoning",
            "Enterprise Host: IBM LinuxONE (s390x) Community Cloud",
        ],
    }

