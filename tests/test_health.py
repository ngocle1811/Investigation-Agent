"""API bootstrap tests."""

from fastapi.testclient import TestClient

from investigation_agent.api.main import app
from investigation_agent.storage import database, vector


def test_liveness() -> None:
    """The liveness endpoint does not require backing services."""

    client = TestClient(app)
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_health_reports_ready_dependencies(monkeypatch) -> None:
    """Readiness is healthy when both connections work."""

    monkeypatch.setattr(database, "check_database", lambda: (True, "ok"))
    monkeypatch.setattr(vector, "check_qdrant", lambda: (True, "ok"))
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "investigation-agent-api",
        "dependencies": {
            "postgres": {"status": "ok", "detail": "ok"},
            "qdrant": {"status": "ok", "detail": "ok"},
        },
    }


def test_health_reports_degraded_dependency(monkeypatch) -> None:
    """Readiness exposes a failed dependency without crashing the API."""

    monkeypatch.setattr(database, "check_database", lambda: (False, "OperationalError"))
    monkeypatch.setattr(vector, "check_qdrant", lambda: (True, "ok"))
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
