
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.ai_agent import investigate_alert
from app.detection.engine import detect_brute_force
from app.parsers.linux_auth import parse_linux_auth_log


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_PATH = PROJECT_ROOT / "sample_logs" / "linux_auth.log"


def run_pipeline(
    log_path: Path = DEFAULT_LOG_PATH,
    use_ai: bool = True,
) -> dict:
    """Parse logs, detect threats, and optionally investigate alerts with AI."""

    with log_path.open("r", encoding="utf-8") as log_file:
        return run_pipeline_lines(log_file, use_ai=use_ai)


def run_pipeline_text(text: str, use_ai: bool = False) -> dict:
    """Run the standard parser and detector against supplied log text."""
    return run_pipeline_lines(text.splitlines(), use_ai=use_ai)


def run_pipeline_lines(lines, use_ai: bool = False) -> dict:
    events = []
    base_year = datetime.now(timezone.utc).year

    for line in lines:
        event = parse_linux_auth_log(line)
        if event is None:
            continue

        # Syslog timestamps do not contain a year or timezone.
        parsed_time = datetime.strptime(
            f"{base_year} {event['timestamp']}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
        event["timestamp"] = parsed_time.isoformat()
        events.append(event)

    alerts = detect_brute_force(events)
    failures_by_source = defaultdict(list)
    for event in events:
        if event["event_type"] == "ssh_login_failed":
            failures_by_source[event["source_ip"]].append(
                datetime.fromisoformat(event["timestamp"])
            )
    failure_summary = []
    detection_window = timedelta(minutes=5)
    for source_ip, timestamps in failures_by_source.items():
        timestamps.sort()
        start = 0
        maximum_in_window = 0
        for end, timestamp in enumerate(timestamps):
            while timestamp - timestamps[start] >= detection_window:
                start += 1
            maximum_in_window = max(maximum_in_window, end - start + 1)
        failure_summary.append({
            "source_ip": source_ip,
            "failed_attempts": len(timestamps),
            "maximum_in_five_minute_window": maximum_in_window,
            "first_seen": timestamps[0].isoformat(),
            "last_seen": timestamps[-1].isoformat(),
        })

    # Add an AI investigation report to each detection alert.
    for alert in alerts:
        alert["ai_investigation"] = None

        if use_ai:
            try:
                alert["ai_investigation"] = investigate_alert(alert)
            except (RuntimeError, TimeoutError) as exc:
                alert["ai_investigation_error"] = str(exc)

    return {
        "events_processed": len(events),
        "alerts_generated": len(alerts),
        "ai_enabled": use_ai,
        "events": events,
        "alerts": alerts,
        "rule_explanation": {
            "rule_id": "SF-SSH-001",
            "threshold": 5,
            "window_minutes": 5,
            "summary": (
                "Triggers when at least 5 failed SSH logins from one source IP "
                "occur within a 5-minute window. Repeated failures are suspicious "
                "evidence, not proof of a successful compromise."
            ),
        },
        "failed_event_summary": failure_summary,
    }


if __name__ == "__main__":
    result = run_pipeline()
    print(json.dumps(result, indent=2))
