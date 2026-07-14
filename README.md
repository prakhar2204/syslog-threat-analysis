# SysLog Threat Analysis

Real-Time Syslog Monitoring & Threat Detection Dashboard

A lightweight, offline-capable SOC investigation platform that ingests syslog files, detects threats via a rule-based engine with MITRE ATT&CK mapping, correlates alerts into incidents, and presents findings through a professional security operations dashboard.

## Architecture

```
┌─────────────┐    ┌──────────────────────────────────────────────┐
│  Log File   │───▶│                  Backend                     │
│  (syslog)   │    │                                              │
└─────────────┘    │  Parser → Detection → Correlation → Analysis │
                   │                                              │
                   │  FastAPI REST API + WebSocket                 │
                   └──────────────┬───────────────────────────────┘
                                  │
                   ┌──────────────▼───────────────────────────────┐
                   │              Frontend                        │
                   │  React + TypeScript + TailwindCSS + Recharts │
                   └──────────────────────────────────────────────┘
```

## Features

- **Multi-format log parsing** — auth.log, syslog, Apache access/error logs
- **15 detection rules** with MITRE ATT&CK technique mapping
- **Incident correlation** — brute force, account compromise, privilege escalation, web recon
- **Deterministic analysis** — confidence scoring, risk classification, template-based reasoning
- **Real-time dashboard** — WebSocket-driven live updates
- **Log explorer** — search, filter, paginate, expand to raw log + triggered rules
- **Incident investigation** — timeline, reasoning, recommendations, related logs
- **Export** — JSON, CSV, PDF incident reports

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React, TypeScript, TailwindCSS, Recharts, Lucide Icons, React Router |
| Backend | Python, FastAPI, Pydantic |
| Processing | Regex, Pandas |
| Deployment | Netlify (frontend), Render (backend) |

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 20+

### Backend

```bash
cd backend
pip install -r requirements.txt
python generate_sample_logs.py
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** in your browser.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/version` | Project metadata |
| GET | `/ready` | Readiness probe with subsystem status |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/logs` | Filtered/paginated log entries |
| GET | `/api/logs/{id}` | Log detail with triggered rules |
| GET | `/api/alerts` | Alert list |
| POST | `/api/alerts/action` | Acknowledge/resolve alerts |
| GET | `/api/incidents` | Incident list |
| GET | `/api/incidents/{id}` | Full incident detail |
| POST | `/api/monitor/start` | Start file monitoring |
| POST | `/api/monitor/stop` | Stop monitoring |
| GET | `/api/files` | Available log files |
| GET | `/api/export/{format}` | Export JSON/CSV/PDF |
| POST | `/api/clear` | Reset all data |
| WS | `/ws` | Real-time updates |

## Deployment

### Frontend → Netlify

The `netlify.toml` at project root handles build configuration and SPA routing.

Set the environment variable in Netlify:
- `VITE_API_BASE_URL` = your Render backend URL

### Backend → Render

The `render.yaml` at project root defines the web service.

Set environment variables in Render:
- `CORS_ORIGINS` = your Netlify frontend URL
- `ENVIRONMENT` = `production`

## Project Structure

```
syslog-a/
├── backend/
│   ├── main.py                 # FastAPI entry point
│   ├── config.py               # Centralized configuration
│   ├── api/                    # REST API routes and schemas
│   ├── models/                 # Pydantic data models
│   ├── parser/                 # Multi-format log parser
│   ├── detection/              # Threat detection rules and engine
│   ├── correlation/            # Incident correlation engine
│   ├── analysis/               # Confidence scoring and reasoning
│   ├── services/               # Pipeline orchestrator and file watcher
│   ├── websocket/              # WebSocket connection manager
│   ├── reports/                # JSON/CSV/PDF export
│   └── utils/                  # Shared utilities
├── frontend/
│   ├── src/
│   │   ├── components/         # Reusable UI components
│   │   ├── pages/              # Dashboard, Logs, Incidents, Reports, Settings
│   │   ├── context/            # Global state management
│   │   ├── hooks/              # WebSocket hook
│   │   ├── services/           # API client
│   │   ├── types/              # TypeScript interfaces
│   │   └── utils/              # Formatting utilities
│   └── index.html
├── .github/workflows/ci.yml   # CI pipeline
├── netlify.toml                # Netlify deployment
└── render.yaml                 # Render deployment
```

## License

This project is for educational and demonstration purposes.
