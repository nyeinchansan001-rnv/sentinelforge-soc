from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.pipeline import run_pipeline, run_pipeline_text


app = FastAPI(
    title="SentinelForge SOC",
    description=(
        "AI-assisted SOC investigation API "
        "for Linux authentication logs."
    ),
    version="1.0.0",
)

LOCAL_FRONTEND_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)


def get_frontend_origins() -> list[str]:
    configured = os.getenv("FRONTEND_ORIGINS", "")
    origins = [origin.strip().rstrip("/") for origin in configured.split(",")]
    return list(dict.fromkeys([*LOCAL_FRONTEND_ORIGINS, *(o for o in origins if o)]))


app.add_middleware(
    CORSMiddleware,
    allow_origins=get_frontend_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALLOWED_LOG_DIR = (PROJECT_ROOT / "sample_logs").resolve()
MAX_UPLOAD_BYTES = 1024 * 1024
MAX_LOG_LINES = 10_000
ALLOWED_SOURCE_IPS = {
    "10.0.0.10",
    "192.0.2.10",
    "192.168.1.50",
    "198.51.100.25",
    "203.0.113.50",
}


class AnalyzeRequest(BaseModel):
    log_path: str | None = None
    mode: Literal["sample", "scenario", "custom"] = "sample"
    scenario: Literal["normal", "failures", "success_after_failures"] = "normal"
    failed_attempts: int = Field(default=5, ge=0, le=20)
    source_ip: str = "192.0.2.10"
    interval_minutes: int = Field(default=5, ge=1, le=30)
    include_success: bool = False
    use_ai: bool = True


def _validate_custom_input(request: AnalyzeRequest) -> None:
    if request.mode == "custom" and request.source_ip not in ALLOWED_SOURCE_IPS:
        raise HTTPException(
            status_code=422,
            detail="Choose a source IP from the allowed private and documentation addresses.",
        )


def _make_log_lines(
    failed_attempts: int,
    source_ip: str,
    interval_minutes: int,
    include_success: bool,
) -> list[str]:
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    lines = []
    for index in range(failed_attempts):
        offset = interval_minutes * index / max(failed_attempts - 1, 1)
        timestamp = now - timedelta(minutes=interval_minutes - offset)
        lines.append(
            f"{timestamp.strftime('%b %d %H:%M:%S')} lab-host "
            f"sshd[{2200 + index}]: Failed password for invalid user analyst "
            f"from {source_ip} port {54000 + index} ssh2"
        )
    if include_success:
        timestamp = now + timedelta(seconds=30)
        lines.append(
            f"{timestamp.strftime('%b %d %H:%M:%S')} lab-host "
            f"sshd[2299]: Accepted password for analyst from {source_ip} "
            "port 55000 ssh2"
        )
    return lines


def _scenario_lines(scenario: str) -> list[str]:
    if scenario == "normal":
        return _make_log_lines(2, "192.0.2.10", 5, True)
    if scenario == "failures":
        return _make_log_lines(5, "198.51.100.25", 4, False)
    return _make_log_lines(5, "203.0.113.50", 4, True)


@app.get("/")
def health_check():
    return {
        "status": "online",
        "project": "SentinelForge SOC",
        "message": "SOC investigation API is running.",
    }


@app.post("/api/logs/preview")
def preview_custom_logs(request: AnalyzeRequest):
    if request.mode != "custom":
        raise HTTPException(status_code=422, detail="Preview requires custom mode.")
    _validate_custom_input(request)
    lines = _make_log_lines(
        request.failed_attempts,
        request.source_ip,
        request.interval_minutes,
        request.include_success,
    )
    return {"lines": lines, "data_origin": "synthetic"}


@app.post("/api/analyze")
def analyze_logs(request: AnalyzeRequest):
    try:
        if request.log_path is not None:
            log_path = Path(request.log_path).expanduser().resolve()
            if not log_path.is_relative_to(ALLOWED_LOG_DIR):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Access denied: log files must be "
                        "inside the approved sample_logs directory."
                    ),
                )
            if log_path.suffix.lower() != ".log":
                raise HTTPException(status_code=400, detail="Only .log files are allowed.")
            if not log_path.is_file():
                raise HTTPException(status_code=404, detail="Log file not found.")
            result = run_pipeline(log_path=log_path, use_ai=request.use_ai)
        elif request.mode == "sample":
            result = run_pipeline(use_ai=request.use_ai)
        elif request.mode == "scenario":
            lines = _scenario_lines(request.scenario)
            result = run_pipeline_text("\n".join(lines), use_ai=request.use_ai)
        else:
            _validate_custom_input(request)
            lines = _make_log_lines(
                request.failed_attempts,
                request.source_ip,
                request.interval_minutes,
                request.include_success,
            )
            result = run_pipeline_text("\n".join(lines), use_ai=request.use_ai)

        result["data_origin"] = "sample" if request.mode == "sample" else "synthetic"
        return result
    except HTTPException:
        raise
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Log file not found.") from exc
    except (ValueError, OSError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Unable to process the requested log file.",
        ) from exc


@app.post("/api/analyze/upload")
async def analyze_uploaded_log(
    request: Request,
    filename: str = Query(..., min_length=1, max_length=255),
    use_ai: bool = Query(False),
):
    if "/" in filename or "\\" in filename or Path(filename).name != filename:
        raise HTTPException(status_code=400, detail="Provide a .log filename without a path.")
    if Path(filename).suffix.lower() != ".log":
        raise HTTPException(status_code=400, detail="Only .log files are allowed.")

    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Log files must be 1 MiB or smaller.")
        content.extend(chunk)
    try:
        text = bytes(content).decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="The log file must use UTF-8 text encoding.") from exc

    lines = text.splitlines()
    if len(lines) > MAX_LOG_LINES:
        raise HTTPException(status_code=413, detail=f"Log files may contain at most {MAX_LOG_LINES} lines.")
    if "\x00" in text:
        raise HTTPException(status_code=400, detail="The uploaded file contains invalid text data.")
    try:
        result = run_pipeline_text(text, use_ai=use_ai)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail="Unable to parse the uploaded log file.") from exc
    if result["events_processed"] == 0:
        raise HTTPException(
            status_code=422,
            detail="No supported Linux SSH authentication events were found in the log file.",
        )
    result["data_origin"] = "uploaded"
    result["ignored_lines"] = len(lines) - result["events_processed"]
    return result
