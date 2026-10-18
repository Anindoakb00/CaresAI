import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AccessEvent, Alert, ModelMetadata, Patient, PatientAssignment, User
from .ml import get_detector
from .risk import assess_risk
from .security import hash_password


DEMO_USERS = [
    ("admin@careshield.demo", "ShieldAdmin!2026", "Avery Morgan", "administrator", "Operations"),
    ("doctor@careshield.demo", "DoctorDemo!2026", "Dr. Maya Chen", "doctor", "Cardiology"),
    ("nurse@careshield.demo", "NurseDemo!2026", "Jordan Patel", "nurse", "Cardiology"),
    ("analyst@careshield.demo", "AnalystDemo!2026", "Riley Brooks", "security_analyst", "Security"),
]


def seed_demo(db: Session) -> None:
    users: dict[str, User] = {}
    for email, password, display_name, role, department in DEMO_USERS:
        user = db.scalar(select(User).where(User.email == email))
        if not user:
            user = User(email=email, password_hash=hash_password(password), display_name=display_name, role=role, department=department, demo_account=True)
            db.add(user)
            db.flush()
        users[email] = user

    patients = list(db.scalars(select(Patient)).all())
    if not patients:
        patient_rows = [
            ("SYN-1001", "Amara", "Rivera", "50-59", "Cardiology", users["doctor@careshield.demo"].id),
            ("SYN-1002", "Noah", "Kim", "60-69", "Cardiology", users["doctor@careshield.demo"].id),
            ("SYN-1003", "Leila", "Morgan", "40-49", "Neurology", users["doctor@careshield.demo"].id),
            ("SYN-1004", "Elias", "Patel", "70-79", "Cardiology", users["doctor@careshield.demo"].id),
            ("SYN-1005", "Sofia", "Davis", "30-39", "Oncology", users["doctor@careshield.demo"].id),
            ("SYN-1006", "Milo", "Thompson", "50-59", "Cardiology", users["doctor@careshield.demo"].id),
        ]
        patients = [Patient(patient_reference=ref, first_name=first, last_name=last, age_band=age, department=dept, assigned_clinician_id=clinician) for ref, first, last, age, dept, clinician in patient_rows]
        db.add_all(patients)
        db.flush()
    existing_assignments = db.scalar(select(PatientAssignment.id).limit(1))
    if not existing_assignments:
        for patient in patients[:4]:
            db.add(PatientAssignment(user_id=users["doctor@careshield.demo"].id, patient_id=patient.id, policy="assigned-care"))
        for patient in patients[:3]:
            db.add(PatientAssignment(user_id=users["nurse@careshield.demo"].id, patient_id=patient.id, policy="care-team"))
        db.flush()

    if not db.scalar(select(AccessEvent.id).limit(1)):
        doctor = users["doctor@careshield.demo"]
        patient = patients[0]
        normal = assess_risk(action="view", authorized=True)
        event = AccessEvent(actor_id=doctor.id, actor_role=doctor.role, actor_department=doctor.department, action="view", resource_reference=patient.patient_reference, patient_id=patient.id, authorization_result="allowed", record_count=1, risk_score=normal.score, severity=normal.severity, detection_signals=json.dumps(normal.signals), explanation=normal.explanation, response_result="allowed", event_kind="access", event_timestamp=datetime.now(timezone.utc) - timedelta(minutes=18), ml_anomaly_score=8)
        db.add(event)
        db.flush()
    detector = get_detector()
    if not db.scalar(select(ModelMetadata.id).limit(1)):
        db.add(ModelMetadata(version="isolation-forest-v1", model_type="IsolationForest", status=detector.status, evaluation_metrics=json.dumps(detector.metrics)))
    db.commit()

