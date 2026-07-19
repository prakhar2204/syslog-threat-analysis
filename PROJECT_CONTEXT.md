# SysLog Threat Analysis - Project Handoff Document

## 1. Overall Architecture
The project is a professional SOC (Security Operations Center) Investigation Platform designed for real-time threat detection, correlation, and analysis from syslog and other log files.
- **Backend:** Python-based FastAPI application serving both REST APIs and real-time WebSockets. Features a modular, multi-file event ingestion pipeline, a detection engine with configurable rules, an incident correlation engine, and an Explainable Security Intelligence Engine (ESIE) for evidence collection and automated reasoning. Data persistence is currently managed in-memory via application state (simulated DB).
- **Frontend:** React application built with Vite and Tailwind CSS. Employs Context API for state management and custom WebSocket hooks for real-time, non-blocking UI updates. Focuses on actionable intelligence rather than raw analytics.

## 2. Folder Structure
```
/
├── backend/
│   ├── analysis/       # Evidence Engine, Incident Builder, Confidence Scoring
│   ├── api/            # FastAPI REST routes and WebSocket endpoints
│   ├── correlation/    # Correlation Engine
│   ├── detection/      # Threat Detection Engine
│   ├── models/         # Pydantic data models
│   ├── parser/         # Log parsing logic
│   ├── reports/        # Export and reporting
│   ├── services/       # LogWatcher (multi-file), MonitorManager, Pipeline
│   ├── utils/          # Helpers
│   ├── main.py         # Application entry point
│   ├── config.py       # Configuration
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── components/
    │   │   ├── charts/         # Dashboard analytics charts
    │   │   ├── dashboard/      # Active Threat Center, Threat Summary, Log Stream
    │   │   ├── investigation/  # Detection Explanation, IOC Panel
    │   │   ├── layout/         # Header, Sidebar, Layout wrappers
    │   │   ├── monitoring/     # Pipeline Visualizer, Monitoring Status
    │   │   ├── notifications/  # Threat Banner, Notification Toasts
    │   │   └── simulation/     # Simulation Summary
    │   ├── context/    # AppContext, ThemeContext, NotificationContext
    │   ├── hooks/      # useWebSocket
    │   ├── pages/      # Dashboard, Incidents, Logs, Simulator, etc.
    │   ├── services/   # api.ts (REST client)
    │   ├── types/      # TypeScript interfaces matching backend models
    │   ├── utils/      # formatters.ts
    │   ├── App.tsx     # Router and providers
    │   └── index.css   # Tailwind + Theme variables
    ├── tsconfig.json
    └── package.json
```

## 3. Implementation Status
- **Backend:** Stable and fully functional. Multi-file monitoring, dynamic log file discovery, log parsing, threat detection, correlation, evidence collection, and API/WebSocket communication are complete and verified.
- **Frontend:** Stable and fully functional. Phase 5.3 (Live Threat Intelligence Experience) is successfully completed. The dashboard operates as a professional SOC console with real-time updates, enhanced incident drill-downs, dynamic notifications, and prepared infrastructure for theming.

## 4. Completed Features
- **Multi-File Monitoring Engine:** Simultaneous multi-file tracking, dynamic auto-discovery, and per-file offset tracking.
- **Detection & Correlation:** Rule-based detection, incident generation, and multi-stage attack correlation.
- **Evidence Intelligence:** Automated IOC extraction, matched condition highlighting, and confidence scoring.
- **Active Threat Center:** Dedicated UI for high-priority active incidents.
- **Live Notifications:** Non-blocking toasts and critical threat banners.
- **Enhanced Incident UI:** Rich incident cards, attack timelines, grouped evidence sections, and "Why was this detected?" explanations.
- **IOC Intelligence Panel:** Aggregated table of extracted IOCs, occurrences, and MITRE mapping.
- **Simulation Engine:** Built-in attack simulation with automated post-simulation summaries.
- **Theme Infrastructure:** `ThemeContext` and CSS variables configured for light/dark mode persistence.

## 5. Pending Tasks
- **Full UI Redesign:** Dark/Light mode infrastructure is in place, but a comprehensive visual overhaul of components to maximize the aesthetic appeal of the theme is pending.
- **Database Integration:** Transition from in-memory simulated state to a persistent database (e.g., PostgreSQL/MongoDB) for long-term data retention and scalability.

## 6. Important Design Decisions
- **Deterministic Polling:** LogWatcher relies on periodic directory scanning and file polling rather than OS-specific file system events (e.g., inotify) to ensure compatibility with PaaS environments like Render.
- **In-Memory State:** For the current phase, state is held in memory to accelerate development and focus on architecture/UX.
- **WebSocket UX:** The UI is designed to never require a manual refresh. State context merges REST data (on load) with WebSocket deltas seamlessly.
- **Frontend-Driven Formatting:** Timestamps are managed as ISO strings by the backend and converted to the analyst's local timezone on the frontend.

## 7. APIs and Endpoints
**REST (`/api/`)**
- `/stats` - Dashboard analytics
- `/logs`, `/logs/{id}` - Paginated log retrieval
- `/alerts` - Alerts management
- `/incidents`, `/incidents/{id}` - Incident management
- `/monitor/status`, `/monitor/start`, `/monitor/stop`, `/monitor/pipeline` - LogWatcher control
- `/simulation/scenarios`, `/simulation/start`, `/simulation/status` - Simulator control
- `/evidence`, `/evidence/{id}`, `/evidence/by-incident/{id}` - Evidence intelligence
- `/observations`, `/observations/promote` - Sub-threshold observation tracking

**WebSocket (`/ws`)**
- Emits real-time messages: `new_logs`, `new_alert`, `new_incident`, `stats_update`, `evidence_created`, `observation_promoted`.

## 8. Environment Variables
- **Frontend:** `VITE_API_BASE_URL` (Target backend URL. If omitted, assumes relative `/api`).
- **Backend:** Configured via `config.py` (Host, Port, default log folders).

## 9. Database Schema (Current In-Memory Data Models)
Core entities (see `backend/models/` and `frontend/src/types/index.ts`):
- **LogEntry:** Raw log data, parsed fields, severity.
- **Alert:** Single detection rule match.
- **Incident:** Correlated alerts, source/target tracking, reasoning, timeline, mitigation recommendations.
- **Observation:** Sub-threshold suspicious activity tracking.
- **Evidence:** Matched conditions, extracted IOCs, raw log references, confidence scoring tied to incidents.

## 10. Known Bugs & Limitations
- **Memory Overhead:** As the state is currently in-memory, monitoring a massive volume of logs or running the application continuously for days without a restart may lead to high RAM utilization.
- **Stateless Deployments:** If the backend (Render) goes to sleep or restarts, all current incident and log history will be cleared.

## 11. Deployment Status
- **Backend:** Deployed on Render (`https://syslog-threat-analysis.onrender.com/`). API docs available at `/docs`.
- **Frontend:** Deployed on Netlify.

## 12. Current Branch/State
- Project is in a stable, functional state post-Phase 5.3 completion. No broken code or unresolved TypeScript errors.
- **Recent modifications:** `frontend/src/components/*` (Dashboards, Investigation panels, Notifications), `frontend/src/pages/*` (Dashboard, Incidents, Simulator), and `frontend/src/context/*`.

## 13. Coding Conventions
- **TypeScript:** Strict typing used across the frontend. Interfaces perfectly mirror Python Pydantic models.
- **Styling:** Tailwind CSS with custom theme variables (e.g., `text-severity-critical`, `bg-bg-card`).
- **React:** Functional components, heavy use of Context API to prevent prop drilling, custom hooks (`useWebSocket`, `useTheme`, `useNotifications`).
- **Python:** FastAPI asynchronous routes, type hinting, object-oriented services (`LogWatcher`, `MonitorManager`).
