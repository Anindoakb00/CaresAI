from app.risk import assess_risk, severity_for

from conftest import login


def test_login_and_me(client):
    response = login(client)
    assert response.json()["user"]["role"] == "doctor"
    assert client.get("/api/auth/me").status_code == 200


def test_invalid_login(client):
    response = client.post("/api/auth/login", json={"email": "doctor@careshield.demo", "password": "wrong-password"})
    assert response.status_code == 401


def test_logout_expires_session(client):
    login(client)
    csrf = client.cookies.get("careshield_csrf")
    response = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_unauthorized_api_access(client):
    client.cookies.clear()
    assert client.get("/api/dashboard/summary").status_code == 401


def test_doctor_assigned_patient_and_denial(client):
    login(client)
    patients = client.get("/api/patients").json()
    assert patients
    assert client.get(f"/api/patients/{patients[0]['id']}").status_code == 200
    client.cookies.clear()
    login(client, "analyst@careshield.demo", "AnalystDemo!2026")
    unassigned = next(p for p in client.get("/api/patients").json() if p["patient_reference"] == "SYN-1005")
    client.cookies.clear()
    login(client)
    assert client.get(f"/api/patients/{unassigned['id']}").status_code == 403


def test_role_permissions_and_real_dashboard(client):
    login(client, "analyst@careshield.demo", "AnalystDemo!2026")
    assert client.get("/api/events").status_code == 200
    assert client.get("/api/dashboard/summary").json()["total_events"] >= 1
    client.cookies.clear()
    login(client)
    assert client.get("/api/events").status_code == 403


def test_risk_boundaries_and_explanations():
    assert severity_for(0) == "low"
    assert severity_for(24) == "low"
    assert severity_for(25) == "medium"
    assert severity_for(50) == "high"
    assert severity_for(80) == "critical"
    normal = assess_risk(action="view", authorized=True)
    export = assess_risk(action="export", authorized=False)
    assert normal.score == 5
    assert export.score == 95
    assert "unauthorized" in export.explanation.lower()


def test_normal_demo_persists_event(client):
    login(client)
    csrf = client.cookies.get("careshield_csrf")
    response = client.post("/api/demo/normal-access", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert response.json()["event"]["risk_score"] == 5


def test_suspicious_demo_creates_alert(client):
    client.cookies.clear()
    login(client, "analyst@careshield.demo", "AnalystDemo!2026")
    csrf = client.cookies.get("careshield_csrf")
    response = client.post("/api/demo/suspicious-access", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    assert response.json()["alert"]["severity"] in {"high", "critical"}
    assert client.get("/api/alerts").json()


def test_unauthorized_export_is_denied_without_payload(client):
    csrf = client.cookies.get("careshield_csrf")
    response = client.post("/api/demo/unauthorized-export", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is False
    assert body["response"] == "blocked"
    assert body["export_payload"] is None
    assert body["severity"] == "critical"


def test_alert_acknowledge_and_resolve(client):
    alerts = client.get("/api/alerts").json()
    alert_id = alerts[0]["id"]
    csrf = client.cookies.get("careshield_csrf")
    acknowledged = client.post(f"/api/alerts/{alert_id}/acknowledge", json={"note": "Reviewed during demo"}, headers={"X-CSRF-Token": csrf})
    assert acknowledged.status_code == 200
    resolved = client.post(f"/api/alerts/{alert_id}/resolve", json={"note": "Synthetic scenario closed"}, headers={"X-CSRF-Token": csrf})
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"


def test_model_status_and_privacy_minimization(client):
    status = client.get("/api/model/status")
    assert status.status_code == 200
    assert "patient" not in str(status.json()["features"]).lower()
    alerts = client.get("/api/alerts").json()
    assert all("password" not in str(alert).lower() for alert in alerts)


def test_reset_preserves_accounts(client):
    client.cookies.clear()
    login(client, "admin@careshield.demo", "ShieldAdmin!2026")
    csrf = client.cookies.get("careshield_csrf")
    response = client.post("/api/demo/reset", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    client.cookies.clear()
    assert login(client, "doctor@careshield.demo", "DoctorDemo!2026").status_code == 200

