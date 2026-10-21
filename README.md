# SentinelForge SOC

**An AI-Assisted Security Operations Center (SOC) Investigation Dashboard**

SentinelForge SOC is a cybersecurity portfolio project that analyzes Linux authentication logs, detects potential SSH brute-force activity, and generates AI-assisted investigation reports using a locally running language model.

> **Disclaimer:** This project uses synthetic sample logs for demonstration and educational purposes. Alerts indicate suspicious patterns, not confirmed malicious activity.

## Features

- **Linux Authentication Log Parsing** — Extracts SSH login failures, successful logins, and invalid-user events.
- **Rule-Based Detection** — Detects five or more failed SSH login attempts from the same source IP within a five-minute rolling window.
- **Alert Prioritization** — Generates high-severity alerts for matching brute-force patterns.
- **AI-Assisted Investigation** — Uses a locally hosted Ollama model to summarize evidence, assess risk, and suggest next investigative steps.
- **REST API** — Provides log analysis through FastAPI endpoints.
- **API Security Validation** — Restricts requested log files to the approved sample log directory and accepts only `.log` files.
- **Automated Tests** — Tests parsing, detection logic, and API security behavior.

## Technology Stack

| Component | Technology |
|---|---|
| Backend API | Python, FastAPI |
| Frontend | React, Vite |
| AI inference | Ollama, `llama3.2:3b` |
| Detection | Python rule-based logic |
| Testing | pytest |
| Data source | Synthetic Linux authentication logs |

## Detection Logic

The current detection rule looks for:

- Five or more failed SSH login attempts.
- The same source IP address.
- A five-minute rolling time window.
- Timezone-aware event timestamps.

When the rule matches, the API generates an `SF-SSH-001` high-severity alert.

This is a basic detection rule for a learning project. It does not establish that an attacker successfully compromised a system.

## AI Investigation Workflow

1. Read the sample authentication log.
2. Parse raw entries into normalized events.
3. Apply the brute-force detection rule.
4. Generate an alert containing the detected evidence.
5. Send the alert context to the local Ollama model when AI analysis is enabled.
6. Return the alert and investigation report through the API.
7. Display the results in the dashboard.

AI-generated reports are advisory. Investigators should verify the evidence independently before taking action.

## Run Locally

### 1. Prerequisites

- Python 3.12 or a compatible Python version.
- Node.js and npm.
- Ollama installed locally if you want AI-generated reports.

### 2. Start the backend

```bash
cd backend
source .venv/bin/activate
python -m uvicorn app.api:app --reload
```

API: `http://127.0.0.1:8000`

Interactive API documentation: `http://127.0.0.1:8000/docs`

### 3. Run the tests

From the `backend` directory:

```bash
python -m pytest -v
```

### 4. Start the frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, normally `http://localhost:5173/`.

### 5. Enable local AI analysis

Make sure Ollama is running and the model is available:

```bash
ollama pull llama3.2:3b
ollama list
```

The backend uses the local Ollama generation API. AI analysis requires Ollama to be available; non-AI analysis can be tested with `"use_ai": false`.

## Example API Request

Send a `POST` request to `/api/analyze`:

```json
{
  "use_ai": false
}
```

The API analyzes the bundled sample log and returns processed events and any matching alerts.

## Project Structure

```text
sentinelforge-soc/
├── backend/
│   ├── app/
│   │   ├── detection/
│   │   ├── parsers/
│   │   ├── ai_agent.py
│   │   ├── api.py
│   │   └── pipeline.py
│   ├── sample_logs/
│   └── tests/
├── frontend/
│   └── src/
├── sample_logs/
├── .env.example
├── .gitignore
└── README.md
```

## Limitations

- The current detection logic focuses on a single SSH brute-force pattern.
- Sample events are synthetic and do not represent a real incident.
- The local language model may produce inaccurate conclusions; its output must be reviewed.
- This project does not automatically block IP addresses, isolate hosts, or remediate incidents.
- The dashboard should not be treated as a production-ready SIEM.

## Future Improvements

- Add more detection rules and test cases.
- Support uploaded log files with safe validation.
- Add alert history and investigation status tracking.
- Improve evidence traceability and AI output validation.
- Add deployment documentation and screenshots.

## Author

Cybersecurity portfolio project focused on SOC analysis, log investigation, detection engineering, and local AI-assisted workflows.
