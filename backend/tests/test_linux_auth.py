
from app.parsers.linux_auth import parse_linux_auth_log


def test_failed_login():
    log = (
        "Oct 21 10:30:15 ubuntu "
        "sshd[1234]: Failed password for invalid user admin "
        "from 192.168.1.50 port 54321 ssh2"
    )

    event = parse_linux_auth_log(log)

    assert event is not None
    assert event["event_type"] == "ssh_login_failed"
    assert event["username"] == "admin"
    assert event["source_ip"] == "192.168.1.50"
    assert event["status"] == "failed"


def test_successful_login():
    log = (
        "Oct 21 10:31:00 ubuntu "
        "sshd[1235]: Accepted password for chan "
        "from 192.168.1.20 port 54322 ssh2"
    )

    event = parse_linux_auth_log(log)

    assert event is not None
    assert event["event_type"] == "ssh_login_success"
    assert event["username"] == "chan"
    assert event["status"] == "success"


def test_ignore_unrelated_log():
    log = (
        "Oct 21 10:32:00 ubuntu "
        "systemd[1]: Started Daily Cleanup Service."
    )

    assert parse_linux_auth_log(log) is None



