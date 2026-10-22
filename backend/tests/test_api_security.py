
from pathlib import Path

from fastapi.testclient import TestClient

from app.api import LOCAL_FRONTEND_ORIGINS, app, get_frontend_origins


client = TestClient(app)
SAMPLE_LOG_DIR = Path(__file__).resolve().parents[2] / "sample_logs"


def test_frontend_origins_include_local_and_configured_origins(monkeypatch):
    monkeypatch.setenv(
        "FRONTEND_ORIGINS",
        " https://sentinelforge.example , https://admin.example/ ,https://sentinelforge.example ",
    )

    origins = get_frontend_origins()

    assert origins == [
        *LOCAL_FRONTEND_ORIGINS,
        "https://sentinelforge.example",
        "https://admin.example",
    ]
    assert "*" not in origins


def test_frontend_origins_default_to_localhost(monkeypatch):
    monkeypatch.delenv("FRONTEND_ORIGINS", raising=False)

    assert get_frontend_origins() == list(LOCAL_FRONTEND_ORIGINS)


def test_health_check_is_online():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_rejects_path_outside_sample_logs():
    response = client.post(
        "/api/analyze",
        json={
            "log_path": "/etc/passwd",
            "use_ai": False,
        },
    )

    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]


def test_rejects_non_log_file_inside_sample_logs():
    response = client.post(
        "/api/analyze",
        json={
            "log_path": str(SAMPLE_LOG_DIR / "example.txt"),
            "use_ai": False,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Only .log files are allowed."
    )


def test_rejects_missing_log_file_inside_sample_logs():
    response = client.post(
        "/api/analyze",
        json={
           "log_path": str(SAMPLE_LOG_DIR / "does-not-exist.log"),
            "use_ai": False,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Log file not found."
