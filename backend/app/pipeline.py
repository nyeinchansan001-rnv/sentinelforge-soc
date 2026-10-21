
import json
from datetime import datetime, timezone
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

    events = []
    base_year = datetime.now(timezone.utc).year

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
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
    }


if __name__ == "__main__":
    result = run_pipeline()
    print(json.dumps(result, indent=2))
