
import re
from datetime import datetime
from typing import Any


FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (invalid user )?"
    r"(?P<username>\S+) from (?P<source_ip>\S+)"
)

ACCEPTED_PASSWORD_RE = re.compile(
    r"Accepted (?:password|publickey) for "
    r"(?P<username>\S+) from (?P<source_ip>\S+)"
)

INVALID_USER_RE = re.compile(
    r"Invalid user (?P<username>\S+) from (?P<source_ip>\S+)"
)

SSH_PROCESS_RE = re.compile(r"\bsshd(?:\[(?P<pid>\d+)\])?:")
SYSLOG_PREFIX_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>\S+) "
)


def parse_linux_auth_log(line: str) -> dict[str, Any] | None:
    """Parse a Linux SSH authentication log into a normalized event."""

    line = line.strip()

    if not line:
        return None

    prefix = SYSLOG_PREFIX_RE.search(line)
    ssh_process = SSH_PROCESS_RE.search(line)

    # Only parse SSH daemon events in this initial version.
    if not prefix or not ssh_process:
        return None

    failed = FAILED_PASSWORD_RE.search(line)
    accepted = ACCEPTED_PASSWORD_RE.search(line)
    invalid_user = INVALID_USER_RE.search(line)

    if failed:
        match = failed
        event_type = "ssh_login_failed"
        status = "failed"
    elif accepted:
        match = accepted
        event_type = "ssh_login_success"
        status = "success"
    elif invalid_user:
        match = invalid_user
        event_type = "ssh_invalid_user"
        status = "unknown"
    else:
        return None

    try:
        source_ip = match.group("source_ip")
        username = match.group("username")
    except (IndexError, AttributeError):
        return None

    return {
        "timestamp": prefix.group("timestamp"),
        "hostname": prefix.group("hostname"),
        "process": "sshd",
        "pid": ssh_process.group("pid"),
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "status": status,
        "raw_log": line,
    }
