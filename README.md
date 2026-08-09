# SysLog Threat Analysis

**Real-Time Linux Log Monitoring & Threat Investigation Platform**

A self-contained, offline-capable SOC (Security Operations Centre) tool that reads Linux system logs, detects security threats using a rule-based engine, correlates related alerts into structured incidents, and presents everything through a live analyst dashboard.**.

---

## What This Project Does

Linux servers log every login attempt, command, network event, and error to plain text files in real time. A single brute force attack against SSH can generate hundreds of individual log lines. Without automation, a security analyst has no practical way to identify these patterns in high-volume log data.

This platform solves that problem by:

- Watching log files continuously and processing every new line as it appears
- Applying 15 detection rules (including MITRE ATT&CK-mapped techniques) to identify threats
- Grouping related alerts into single, enriched incidents using time-window correlation
- Presenting each incident with a complete timeline, confidence score, threat score, IOC list, root cause, and recommended response actions
- Pushing all updates to a browser dashboard in real time over WebSocket

The system is fully self-contained — no database, no cloud services, no external APIs required at runtime.

---

## Key Features

- **Multi-format log parsing** — `auth.log`, `syslog`, Apache access log, Apache error log
- **15 detection rules** — SSH brute force, SQL injection, directory traversal, privilege escalation, kernel panic, and more; each mapped to a MITRE ATT&CK technique where applicable
- **Alert correlation** — groups related alerts into incidents using 5 time-window scenarios (brute force, account compromise, web reconnaissance, privilege escalation sequence, repeated service failure)
- **Incident intelligence** — confidence score (4 factors), threat score (10 factors), behavioural pattern detection, attack chain stage tracking, root cause analysis, and prioritized response recommendations
- **IOC extraction** — automatically extracts IP addresses, domains, URLs, file paths, commands, ports, and hashes from log text
- **Real-time dashboard** — sub-second WebSocket updates; no page refresh needed
- **Upload investigation** — drop in any log file and analyze it offline using the same detection pipeline
- **Attack simulator** — generates realistic log traffic for 6 attack scenarios (SSH brute force, account compromise, web recon, SQL injection, directory traversal, firewall burst) for testing and demonstration
- **Report export** — JSON, CSV, and PDF formats

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend language | Python 3.11+ |
| Backend framework | FastAPI 0.115+ with Uvicorn ASGI |
| Data validation | Pydantic v2 |
| PDF export | fpdf2 |
| Frontend language | TypeScript 5 with React 18 |
| CSS framework | TailwindCSS v4 |
| Charts | Recharts |
| Routing | React Router v7 |
| Build tool | Vite 8 |
| Real-time updates | WebSocket (RFC 6455) |
| Frontend hosting | Netlify |
| Backend hosting | Render |

---

## Project Structure

```
syslog-a/
│
├── backend/
│   ├── main.py                  # FastAPI app entry point; CORS, routes, WebSocket, lifespan
│   ├── config.py                # All constants, thresholds, and settings
│   ├── requirements.txt         # Python dependencies
│   ├── generate_sample_logs.py  # Script to regenerate sample log files
│   │
│   ├── api/                     # REST API routes and request/response schemas
│   ├── models/                  # Pydantic models: LogEntry, Alert, Incident, etc.
│   ├── parser/                  # Multi-format log parser (4 regex patterns, auto-detection)
│   ├── detection/               # 15 detection rules + threat engine (pattern + frequency modes)
│   ├── correlation/             # Incident correlation engine (5 time-window scenarios)
│   ├── analysis/                # Confidence scoring, threat scoring, IOC extraction,
│   │                            # behavioural analysis, attack chain, root cause,
│   │                            # smart recommendations, evidence graph
│   ├── services/                # Pipeline orchestrator, log file watcher, attack simulator
│   ├── websocket/               # WebSocket connection manager and broadcast logic
│   ├── reports/                 # JSON, CSV, PDF export generators
│   ├── exports/                 # Output directory for generated reports (auto-created)
│   ├── sample_logs/             # Pre-built sample log files for testing
│   └── utils/                   # Shared formatting and helper utilities
│
├── frontend/
│   ├── index.html               # HTML entry point
│   ├── vite.config.ts           # Vite config; dev proxy for /api and /ws
│   ├── package.json             # Node dependencies and scripts
│   ├── tsconfig.json            # TypeScript configuration
│   └── src/
│       ├── App.tsx              # Root component with router
│       ├── main.tsx             # React entry point
│       ├── index.css            # Global styles
│       ├── pages/               # Dashboard, Logs, Incidents, Upload, Simulator, Settings
│       ├── components/          # Reusable UI components
│       ├── context/             # Global state (AppContext) fed by WebSocket
│       ├── hooks/               # useWebSocket hook
│       ├── services/            # HTTP API client
│       ├── types/               # TypeScript interfaces matching backend models
│       └── utils/               # Date formatting, severity helpers
│
├── netlify.toml                 # Netlify build config and SPA redirect rule
├── render.yaml                  # Render web service definition
└── .github/workflows/           # CI pipeline
```

---

## Local Setup

### Prerequisites

| Tool | Minimum Version | Check |
|---|---|---|
| Python | 3.10 | `python --version` |
| Node.js | 18 | `node --version` |
| npm | 8 | `npm --version` |

> **Windows users:** use `python` and `pip` as shown. On Linux/macOS, you may need `python3` and `pip3`.

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/prakhar2204/syslog-threat-analysis.git
cd syslog-threat-analysis
```

---

### Step 2 — Backend Setup

Open a terminal in the project root.

```bash
# Move into the backend folder
cd backend

# (Recommended) Create a virtual environment
python -m venv .venv

# Activate it
# On Windows:
.venv\Scripts\activate
# On Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

The backend is now ready to start.

---

### Step 3 — Generate Sample Logs (First Run Only)

Sample log files are included in `backend/sample_logs/`. If they are missing or you want to regenerate them:

```bash
# Run this from inside the backend/ folder
python generate_sample_logs.py
```

This creates three files in `backend/sample_logs/`:
- `auth.log` — SSH login events (brute force patterns, successful logins, privilege escalation)
- `syslog` — kernel and service events
- `apache_access.log` — HTTP traffic (web recon, SQL injection, directory traversal patterns)

---

### Step 4 — Start the Backend

```bash
# From inside the backend/ folder
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

You should see output like:

```
INFO  - Starting SysLog Threat Analysis v1.0.0
INFO  - Uvicorn running on http://0.0.0.0:8000
INFO  - Auto-monitoring started: watching backend/sample_logs/
```

The backend is now running at `http://localhost:8000`.

- API documentation (Swagger UI): `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

---

### Step 5 — Frontend Setup

Open a **new terminal** in the project root (keep the backend running in the first terminal).

```bash
# Move into the frontend folder
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```

You should see:

```
VITE v8.x.x  ready in ... ms
➜  Local:   http://localhost:5173/
```

Open **http://localhost:5173** in your browser.

---

### How Frontend Connects to Backend

The Vite dev server automatically proxies:
- All `/api/*` requests → `http://localhost:8000`
- The `/ws` WebSocket connection → `ws://localhost:8000`

No manual URL configuration is needed for local development. The backend and frontend just need to be running at the same time.

---

## Environment Variables

### Backend (`backend/.env`)

The file `backend/.env` is read automatically on startup. The defaults work for local development without any changes.

| Variable | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `development` | Set to `production` to disable Swagger UI |
| `LOG_LEVEL` | `INFO` | Python logging level (`DEBUG`, `INFO`, `WARNING`) |
| `PORT` | `8000` | Port the server listens on |
| `CORS_ORIGINS` | _(empty)_ | Extra allowed origins (comma-separated); not needed locally |

### Frontend (`frontend/.env.development`)

| Variable | Default | Description |
|---|---|---|
| `VITE_API_BASE_URL` | _(empty)_ | Leave empty for local dev; Vite proxy handles routing |

---

## How to Test the Project

Once both backend and frontend are running, follow these steps to verify the system works end to end.

### Option A — Use the Attack Simulator (Easiest)

1. Open the browser at `http://localhost:5173`
2. Click **Simulator** in the left navigation
3. Choose a scenario — for example, **SSH Brute Force**
4. Click **Start Simulation**
5. Watch the **Dashboard** — within a few seconds you will see:
   - New log entries appear in the live log stream
   - An alert count increment
   - A new incident appear with severity **HIGH**
6. Click the incident to open the **Investigation Workspace**
   - Timeline shows each failed login attempt
   - Threat score, confidence score, root cause, and recommendations are populated

### Option B — Upload a Sample Log File

1. Click **Upload** in the navigation
2. Drag and drop `backend/sample_logs/auth.log` into the upload area
3. Click **Analyze**
4. The system processes the file through the same detection and correlation pipeline
5. A session summary shows how many lines were parsed, how many alerts were raised, and how many incidents were found
6. The incidents are listed below the summary and are fully investigable

### Option C — Live Monitoring (Already Active)

The backend automatically starts monitoring `backend/sample_logs/` when it starts. Any log file placed in that folder, or appended to by the simulator, is picked up within 200 milliseconds.

### What to Verify

| Feature | Where to Check |
|---|---|
| Log parsing | **Logs** page — all entries should have parsed fields (timestamp, IP, severity) |
| Detection | **Dashboard** — alert count increments as simulator runs |
| Correlation | **Incidents** page — multiple alerts grouped into one incident |
| Investigation workspace | Click any incident — timeline, scores, IOCs, root cause, recommendations |
| Real-time updates | Leave Dashboard open while simulator runs — counters update without refresh |
| Export | **Settings** page — click JSON / CSV / PDF export buttons |

---

## API Reference

The full interactive API documentation is available at `http://localhost:8000/docs` when running locally.

Key endpoints:

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Process health check |
| `GET` | `/ready` | Readiness probe with subsystem status |
| `GET` | `/api/stats` | Dashboard statistics (log, alert, incident counts) |
| `GET` | `/api/logs` | Paginated log entries with filter support |
| `GET` | `/api/alerts` | Alert list |
| `GET` | `/api/incidents` | Incident list |
| `GET` | `/api/incidents/{id}` | Full incident detail with timeline, scores, IOCs |
| `POST` | `/api/monitor/start` | Start live log monitoring |
| `POST` | `/api/monitor/stop` | Stop monitoring |
| `POST` | `/api/simulate` | Start attack simulation |
| `DELETE` | `/api/simulate` | Stop simulation |
| `POST` | `/api/upload` | Upload and analyze a single log file |
| `GET` | `/api/export/{format}` | Export report — `json`, `csv`, or `pdf` |
| `POST` | `/api/clear` | Reset all in-memory data |
| `WS` | `/ws` | WebSocket for real-time dashboard updates |

---

## Important Notes

- **Sample logs are included.** Three pre-built log files in `backend/sample_logs/` contain realistic attack patterns and are ready to use immediately.

- **Rule-based detection only.** The system does not use machine learning. Every alert is produced by one of 15 deterministic rules — either a regex pattern match or a frequency threshold over a sliding time window. This means every alert is fully traceable to a specific log line and a specific rule.

- **No database.** All data (parsed logs, alerts, incidents) is held in bounded in-memory buffers. The system starts clean every time the backend restarts. This was a deliberate design choice to keep the system self-contained and deployment-simple.

- **Offline capable.** The system does not make any external API calls at runtime. It can operate in a fully air-gapped environment.

- **Lightweight SOC-style system.** This is not a replacement for an enterprise SIEM. It is a focused tool for monitoring Linux server logs, detecting common attack patterns, and guiding an analyst through the investigation of each incident.

---

## Deployment (Production)

For reference — the system is deployed at:
- **Frontend:** Netlify — built with `npm run build`, served as a static site
- **Backend:** Render — run with `uvicorn main:app --host 0.0.0.0 --port $PORT`

### Required environment variables for production:

**On Render (backend):**
```
ENVIRONMENT=production
CORS_ORIGINS=https://your-frontend.netlify.app
LOG_LEVEL=INFO
```

**On Netlify (frontend):**
```
VITE_API_BASE_URL=https://your-backend.onrender.com
```

The `netlify.toml` and `render.yaml` files in the project root contain the complete deployment configuration.

---

## License

This project was developed for educational and research purposes.
