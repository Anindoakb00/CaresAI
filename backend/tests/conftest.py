import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("db") / "test.sqlite"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["SEED_DEMO_DATA"] = "true"
    # Settings and engine are imported after the environment is prepared.
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


def login(client, email="doctor@careshield.demo", password="DoctorDemo!2026"):
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response

