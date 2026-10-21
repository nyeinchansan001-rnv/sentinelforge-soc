
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.pipeline import run_pipeline


app = FastAPI(
    title="SentinelForge SOC",
    description=(
        "AI-assisted SOC investigation API "
        "for Linux authentication logs."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Only allow log files inside the project's sample_logs directory.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALLOWED_LOG_DIR = (PROJECT_ROOT / "sample_logs").resolve()


class AnalyzeRequest(BaseModel):
    log_path: str | None = None
    use_ai: bool = True


@app.get("/")
def health_check():
    return {
        "status": "online",
        "project": "SentinelForge SOC",
        "message": "SOC investigation API is running.",
    }


@app.post("/api/analyze")
def analyze_logs(request: AnalyzeRequest):
    try:
        if request.log_path is None:
            result = run_pipeline(use_ai=request.use_ai)
        else:
            log_path = Path(
                request.log_path
            ).expanduser().resolve()

            # Reject paths outside the approved directory.
            if not log_path.is_relative_to(ALLOWED_LOG_DIR):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Access denied: log files must be "
                        "inside the approved sample_logs directory."
                    ),
                )

            # Accept only existing .log files.
            if log_path.suffix.lower() != ".log":
                raise HTTPException(
                    status_code=400,
                    detail="Only .log files are allowed.",
                )

            if not log_path.is_file():
                raise HTTPException(
                    status_code=404,
                    detail="Log file not found.",
                )

            result = run_pipeline(
                log_path=log_path,
                use_ai=request.use_ai,
            )

        return result

    except HTTPException:
        raise

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail="Log file not found.",
        ) from exc

    except (ValueError, OSError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Unable to process the requested log file.",
        ) from exc
