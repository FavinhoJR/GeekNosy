from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


def test_health_info_and_authorization_gate():
    settings.inline_worker = False
    with TestClient(app) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        info = client.get("/api/info")
        assert info.status_code == 200

        response = client.post(
            "/api/jobs",
            json={
                "request": {
                    "domains": ["8.8.8.8"],
                    "authorization_confirmed": False,
                }
            },
        )
        assert response.status_code == 400


def test_creates_persistent_job_without_running_it():
    settings.inline_worker = False
    with TestClient(app) as client:
        response = client.post(
            "/api/jobs",
            json={
                "request": {
                    "domains": ["8.8.8.8"],
                    "authorization_confirmed": True,
                    "intensity": "passive",
                }
            },
        )
        assert response.status_code == 202
        job = response.json()
        assert job["status"] == "queued"
        fetched = client.get(f"/api/jobs/{job['id']}")
        assert fetched.status_code == 200
