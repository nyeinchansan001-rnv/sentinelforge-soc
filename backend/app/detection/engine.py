
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


def detect_brute_force(
    events: list[dict[str, Any]],
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[dict[str, Any]]:
    """Detect repeated SSH failures from one source IP.

    Events must have ISO-8601 timestamps with a year,
    such as 2026-10-21T10:30:15+00:00.
    """

    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    failures_by_ip = defaultdict(list)

    for event in events:
        if event.get("event_type") != "ssh_login_failed":
            continue

        source_ip = event.get("source_ip")
        timestamp = event.get("timestamp")

        if not source_ip or not timestamp:
            continue

        try:
            parsed_time = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            # Reject timestamps without a timezone.
            if parsed_time.tzinfo is None:
                continue

            parsed_time = parsed_time.astimezone(timezone.utc)

        except (ValueError, TypeError):
            continue

        failures_by_ip[source_ip].append({
            "timestamp": parsed_time,
            "username": event.get("username", "unknown"),
        })

    alerts = []
    window = timedelta(minutes=window_minutes)

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda item: item["timestamp"])
        start = 0

        for end, failure in enumerate(failures):
            while (
                failure["timestamp"] - failures[start]["timestamp"]
                >= window
            ):
                start += 1

            matching = failures[start:end + 1]

            if len(matching) >= threshold:
                alerts.append({
                    "rule_id": "SF-SSH-001",
                    "alert_type": "ssh_brute_force_suspected",
                    "severity": "high",
                    "source_ip": source_ip,
                    "failed_attempts": len(matching),
                    "window_minutes": window_minutes,
                    "usernames": sorted({
                        item["username"] for item in matching
                    }),
                    "first_seen": matching[0]["timestamp"].isoformat(),
                    "last_seen": failure["timestamp"].isoformat(),
                    "description": (
                        f"{len(matching)} failed SSH login attempts "
                        f"from {source_ip} within "
                        f"{window_minutes} minutes."
                    ),
                })

                # Emit one alert for this source IP in this run.
                break

    return alerts
