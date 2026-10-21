
from datetime import datetime, timedelta, timezone

from app.detection.engine import detect_brute_force


def make_event(minutes_ago, event_type="ssh_login_failed"):
    timestamp = datetime(
        2026, 10, 21, 10, 0, tzinfo=timezone.utc
    ) + timedelta(minutes=minutes_ago)

    return {
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "source_ip": "192.168.1.50",
        "username": "admin",
        "status": "failed",
    }


def test_detect_five_failures():
    events = [make_event(i) for i in range(5)]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SF-SSH-001"
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["severity"] == "high"


def test_ignore_below_threshold():
    events = [make_event(i) for i in range(4)]

    assert detect_brute_force(events) == []


def test_ignore_successful_logins():
    events = [
        make_event(i, event_type="ssh_login_success")
        for i in range(5)
    ]

    assert detect_brute_force(events) == []


def test_ignore_timezone_naive_timestamp():
    event = make_event(0)
    event["timestamp"] = "2026-10-21T10:00:00"

    assert detect_brute_force([event]) == []


def test_exactly_four_failures_do_not_trigger_alert():
    events = [make_event(i) for i in range(4)]

    assert detect_brute_force(events) == []


def test_different_ips_are_counted_separately():
    events = [
        make_event(0),
        make_event(1),
        make_event(2),
        make_event(3),
        make_event(4),
    ]

    # Split failures across two IP addresses.
    for i, event in enumerate(events):
        event["source_ip"] = (
            "192.168.1.50" if i < 3 else "192.168.1.60"
        )

    alerts = detect_brute_force(events)

    assert alerts == []


def test_failures_outside_five_minute_window_do_not_combine():
    events = [
        make_event(-6),
        make_event(-5),
        make_event(-4),
        make_event(-3),
        make_event(0),
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_different_usernames_from_same_ip_are_detected():
    events = [make_event(i) for i in range(5)]

    for i, event in enumerate(events):
        event["username"] = "admin" if i % 2 == 0 else "root"

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 5
