from fastapi.testclient import TestClient

from app.api import MAX_UPLOAD_BYTES, app
from app import pipeline


client = TestClient(app)


def test_custom_preview_generates_parser_compatible_lines():
    response = client.post("/api/logs/preview", json={
        "mode": "custom",
        "failed_attempts": 5,
        "source_ip": "192.0.2.10",
        "interval_minutes": 4,
        "include_success": True,
    })

    assert response.status_code == 200
    assert len(response.json()["lines"]) == 6
    analysis = client.post("/api/analyze", json={
        "mode": "custom",
        "failed_attempts": 5,
        "source_ip": "192.0.2.10",
        "interval_minutes": 4,
        "include_success": True,
        "use_ai": False,
    })
    assert analysis.status_code == 200
    body = analysis.json()
    assert body["events_processed"] == 6
    assert body["alerts_generated"] == 1
    assert body["alerts"][0]["source_ip"] == "192.0.2.10"


def test_custom_builder_enforces_safe_ip_and_ranges():
    bad_ip = client.post("/api/analyze", json={
        "mode": "custom", "source_ip": "8.8.8.8", "use_ai": False,
    })
    too_many = client.post("/api/analyze", json={
        "mode": "custom", "failed_attempts": 21, "use_ai": False,
    })
    assert bad_ip.status_code == 422
    assert too_many.status_code == 422


def test_sample_scenario_uses_real_detection_pipeline():
    expected = {
        "normal": (3, 0),
        "failures": (5, 1),
        "success_after_failures": (6, 1),
    }
    for scenario, (event_count, alert_count) in expected.items():
        response = client.post("/api/analyze", json={
            "mode": "scenario", "scenario": scenario, "use_ai": False,
        })
        assert response.status_code == 200
        body = response.json()
        assert body["data_origin"] == "synthetic"
        assert body["events_processed"] == event_count
        assert body["alerts_generated"] == alert_count
        if scenario == "success_after_failures":
            assert any(event["event_type"] == "ssh_login_success" for event in body["events"])


def test_custom_failures_outside_window_do_not_trigger():
    response = client.post("/api/analyze", json={
        "mode": "custom",
        "failed_attempts": 5,
        "source_ip": "192.0.2.10",
        "interval_minutes": 30,
        "use_ai": False,
    })
    assert response.status_code == 200
    body = response.json()
    assert body["alerts_generated"] == 0
    assert body["failed_event_summary"][0]["maximum_in_five_minute_window"] < 5


def test_upload_analyzes_utf8_log_and_returns_detection():
    lines = "\n".join(
        f"Oct 21 10:0{i}:00 lab-host sshd[{1000 + i}]: Failed password for invalid user analyst from 198.51.100.25 port {50000 + i} ssh2"
        for i in range(5)
    )
    response = client.post(
        "/api/analyze/upload?filename=auth.log",
        content=lines.encode("utf-8"),
        headers={"content-type": "application/octet-stream"},
    )
    assert response.status_code == 200
    assert response.json()["events_processed"] == 5
    assert response.json()["alerts_generated"] == 1
    assert response.json()["data_origin"] == "uploaded"


def test_upload_rejects_extension_path_encoding_size_and_unparseable_content():
    wrong_extension = client.post("/api/analyze/upload?filename=auth.txt", content=b"x")
    traversal = client.post("/api/analyze/upload?filename=..%2Fauth.log", content=b"x")
    bad_encoding = client.post("/api/analyze/upload?filename=auth.log", content=b"\xff")
    too_large = client.post(
        "/api/analyze/upload?filename=auth.log",
        content=b"x" * (MAX_UPLOAD_BYTES + 1),
    )
    invalid_log = client.post("/api/analyze/upload?filename=auth.log", content=b"not an auth event")
    assert wrong_extension.status_code == 400
    assert traversal.status_code == 400
    assert bad_encoding.status_code == 400
    assert too_large.status_code == 413
    assert invalid_log.status_code == 422


def test_upload_enforces_line_limit():
    response = client.post(
        "/api/analyze/upload?filename=auth.log",
        content=(b"unrecognized line\n" * 10_001),
    )
    assert response.status_code == 413
    assert "at most" in response.json()["detail"]


def test_ai_failure_preserves_detection_results(monkeypatch):
    def fail_ai(alert):
        raise ValueError("Ollama returned an invalid response")

    monkeypatch.setattr(pipeline, "investigate_alert", fail_ai)
    response = client.post("/api/analyze", json={
        "mode": "custom",
        "failed_attempts": 5,
        "source_ip": "192.0.2.10",
        "interval_minutes": 4,
        "use_ai": True,
    })
    assert response.status_code == 200
    body = response.json()
    assert body["alerts_generated"] == 1
    assert body["alerts"][0]["ai_investigation_error"] == "Ollama returned an invalid response"
