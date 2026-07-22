# PROJECT_CONTEXT_v2.md
# SysLog Threat Analysis -- Master Handoff Document

> **Source of truth:** Generated from a full read of the live codebase.
> **Date:** 2026-07-22
> **Instructions for AI assistants:** Read this file fully before making any changes. The current source code is always authoritative over this file if they conflict.

---

## 1. Project Overview

### Project Name
**SysLog Threat Analysis**

### Purpose
A professional, offline SOC (Security Operations Center) Investigation Platform that ingests syslog and web-server log files, runs a multi-stage threat detection and correlation pipeline, and presents an actionable analyst dashboard. The emphasis is on **explainability** -- every detection, alert, and incident is traced back to specific log events with human-readable reasoning.

### Current Version
`1.0.0` (see `backend/config.py`)

### Current Development Status
**Phase 5.4 complete. Stable.**
- All backend intelligence engines are implemented and functional.
- All frontend pages exist and render correctly.
- Phase 5.5, Phase 6, and Phase 7 are not yet started.
- No broken builds, no failing imports, no TypeScript errors.

### Project Goals
1. Demonstrate a full-stack, real-time threat detection pipeline without relying on external AI services.
2. Produce human-readable, evidence-backed security reasoning for every incident.
3. Provide a working SOC analyst experience: monitor, detect, correlate, investigate, act.
4. Serve as a portfolio / internship submission piece showcasing security engineering, backend design, and frontend product quality.

### Design Philosophy
- **Explainability over accuracy.** Every detection decision must be traceable to actual log data.
- **Deterministic over probabilistic.** No ML/LLM APIs. All logic is rule-based and auditable.
- **Backend-authoritative.** Intelligence lives in the backend. The frontend only displays it.
- **Simplicity first.** In-memory state, polling-based monitoring, and modular services over premature optimization.
- **SOC-first UX.** The dashboard is designed for security analysts, not generic business users.

### Target Users
- Cybersecurity students and engineers demonstrating SOC tooling.
- Internship evaluators assessing full-stack and security engineering competency.
- Future: small security teams without enterprise SIEM budget.

### Current Scope
- Multi-file log monitoring (syslog, Apache/Nginx, UFW firewall logs, systemd logs).
- Real-time detection, correlation, and incident generation.
- Full incident investigation workspace (evidence, IOCs, attack chains, threat scores, recommendations).
- Attack simulation for development, testing, and demonstrations only.
- Export of reports (JSON, CSV, PDF).

### Future Scope (not yet implemented)
- Real data sources: uploaded log files, live syslog collectors, Filebeat/Wazuh/Fluent Bit.
- Database persistence (PostgreSQL or SQLite).
- User authentication and role-based access.
- Runtime rule management (create/edit/disable rules via UI).

---

## 2. Complete Architecture

### 2.1 Frontend
- **Framework:** React 18 + Vite
- **Styling:** Tailwind CSS v4 with @theme block and CSS custom properties
- **State:** React useReducer via AppContext; no Redux, no Zustand
- **Real-time:** Custom useWebSocket hook with auto-reconnect (3s) and heartbeat ping (30s)
- **Routing:** React Router v6
- **Data:** REST API client (services/api.ts) for initial load; WebSocket pushes deltas
- **Theme:** ThemeContext with data-theme="dark" CSS variable override, persisted to localStorage
- **Notifications:** NotificationContext for non-blocking toasts + ThreatBanner for CRITICAL alerts

### 2.2 Backend
- **Framework:** FastAPI (Python 3.11+)
- **Startup:** Lifespan context manager in main.py auto-starts monitoring on boot
- **API:** REST endpoints under /api/, WebSocket at /ws
- **State:** All in-memory (Python objects). No database.
- **Architecture:** Modular services; each engine is a class with a clear interface; pipeline.py orchestrates them.

### 2.3 Pipeline (end-to-end data flow)

Raw log lines feed into LogWatcher (polling every 200ms, per-file offset tracking, auto-discovers new files), then MonitorManager (session lifecycle), then Pipeline.process_lines() which runs: (1) LogParser.parse_line() -> LogEntry, (2) ThreatEngine.analyze(entry) -> [Alert,...], (2.5) BehaviourAnalyzer.track_event() and IOCEngine.track_event() [accumulate], (3) CorrelationEngine.feed(entry, alerts) -> [Incident,...], (4) IncidentBuilder.enrich(incident) [14-step pipeline per incident], (4.5) EvidenceEngine.collect() -> Evidence, EvidenceGraph updated, IOCEngine updated, (4.6) EvidenceEngine.create_observation() for alerts without incidents, (4.7) EvidenceEngine.check_promotion() for auto-promotion, (4.8) IncidentMerger.merge_candidates(), (4.9) calculate_priority() for SOC queue, (5) WebSocket broadcast: new_logs, new_alert, new_incident, evidence_created, observation_promoted, stats_update.

### 2.4 Detection Engine
**Files:** backend/detection/threat_engine.py + backend/detection/rules.py

15 declarative rules (R001-R015) evaluated against each LogEntry.

| Rule | Name | Severity | MITRE | Status |
|------|------|----------|-------|--------|
| R001 | SSH Brute Force | HIGH | T1110 | OK: >=5 failed SSH logins from same IP in 60s |
| R002 | Successful Login After Failures | CRITICAL | T1110.001 | OK: success after >=3 failures in 60s |
| R003 | Invalid User Login Attempt | MEDIUM | T1078 | OK |
| R004 | Root Login Attempt | HIGH | T1078.003 | OK |
| R005 | Privilege Escalation | HIGH | T1548 | OK: regex on sudo/su |
| R006 | SQL Injection Attempt | CRITICAL | T1190 | OK |
| R007 | Directory Traversal | HIGH | T1083 | OK |
| R008 | Suspicious User Agent | HIGH | T1595 | OK |
| R009 | Port Scan Detected | HIGH | T1046 | **BUG: NO CHECK METHOD -- RULE NEVER FIRES** |
| R010 | Firewall Block | INFO | -- | OK |
| R011 | Kernel Panic | CRITICAL | -- | OK |
| R012 | Disk Full | HIGH | -- | OK |
| R013 | Service Crash | MEDIUM | -- | OK |
| R014 | Multiple Authentication Failures | MEDIUM | T1110 | OK: >=3 auth failures in 60s |
| R015 | Excessive 404 Errors | MEDIUM | T1595.002 | OK: >=10 HTTP 404s in 30s |

Internal state: _failed_logins (IP->timestamps), _404_counts (IP->timestamps); pruned on each check.

### 2.5 Correlation Engine
**File:** backend/correlation/correlation_engine.py

Stateful sliding-window correlator producing Incident objects.

| Scenario | Rules | Threshold | Incident Type |
|----------|-------|-----------|---------------|
| Brute Force | R001, R014 | >=5 events in 60s per IP | Brute Force Attack |
| Account Compromise | R002 | R002 after >=3 failures in 120s | Account Compromise |
| Web Reconnaissance | R015,R008,R007,R006 | >=20 unique paths in 30s per IP | Web Reconnaissance |
| Privilege Escalation | R005 | Any R005 event | Privilege Escalation Sequence |
| Service Failure | R013 | >=3 crashes in 60s per service | Repeated Service Failure |

Thresholds configurable in backend/config.py under CORRELATION_THRESHOLDS.

### 2.6 Evidence Engine
**File:** backend/analysis/evidence_engine.py

**Evidence** (tied to an Incident):
- MatchedCondition objects per rule ("why was this rule triggered?")
- IOC extraction (11 types: IPv4, IPv6, URL, email, domain, filepath, command, hash, port, username, hostname)
- Up to 50 raw log references per Evidence
- collection_confidence score (0-100)
- One Evidence object per Incident (updated as new events arrive)

**Observation** (sub-threshold alerts with no incident):
- Auto-promotes when: event_count >= 3 OR distinct alerts >= 2
- Manual promotion via API (POST /api/observations/promote)
- Status: OPEN -> PROMOTED | DISMISSED

### 2.7 IOC Engine
**File:** backend/analysis/ioc_relationship.py

IOCRelationshipEngine maintains an in-memory cross-linked IOC graph.
- Tracks: ip, username, hostname, service as IOC types
- Cross-links: ip<->user, ip<->host, ip<->service
- Confidence: min(100, occurrences*3 + incidents*15 + rules*10 + alerts*2 + 10)
- Provides: top-N by confidence, related IOC lookup, per-incident IOC list

### 2.8 Attack Chain Detection
**File:** backend/analysis/attack_chain.py

AttackChainDetector maps sequences of incidents to known kill-chain patterns.

| Chain ID | Name | Stages |
|----------|------|--------|
| credential_compromise | Credential Compromise Campaign | recon, brute_force, credential_success, privilege_escalation, persistence |
| web_attack | Web Application Attack Campaign | recon, enumeration, exploitation, data_access, exfiltration |
| service_disruption | Service Disruption Campaign | probing, resource_exhaustion, service_crash, denial_of_service |

Per attacker key (IP + user), tracks stages_seen. Updates incident fields: attack_chain_id, attack_chain_stage, attack_chain_progress, attack_chain_stages_completed, attack_chain_stages_missing, estimated_objective.

**BUG:** The persistence stage of credential_compromise has no rule mapped to it. Chain max progress is 80%.

### 2.9 Threat Scoring
**File:** backend/analysis/threat_scorer.py

10-factor composite score (0-100):

| Factor | Weight | Calculation |
|--------|--------|------------|
| rule_severity | 15% | Severity enum -> 10/30/55/80/100 |
| evidence_quality | 12% | related_event_ids x 8, capped at 100 |
| ioc_quality | 8% | (source_ips + mitre_techniques) x 15 |
| correlation_strength | 12% | (rules + mitre + ips) x 12 |
| attack_stage | 10% | Stage-specific lookup (recon=20 to exfiltration=100) |
| attack_progress | 8% | attack_chain_progress value directly |
| time_density | 10% | Events/sec; >=1 EPS = 100 |
| source_diversity | 8% | source_ips x 25, capped |
| rule_diversity | 10% | triggered_rules x 20, capped |
| event_volume | 7% | total_events x 5, capped |

SOC queue priority assigned globally by calculate_priority() -- ranks all active incidents by threat_score descending.

### 2.10 Behaviour Engine
**File:** backend/analysis/behaviour.py

BehaviourAnalyzer accumulates state across all events and produces per-incident findings.

7 detected patterns:
1. One IP targeting multiple users (>=3 targets) -- automated credential scanning
2. Large event volume from single IP (>=20 events) -- sustained malicious activity
3. Impossible authentication speed (<0.5s between attempts) -- confirms automation
4. Repeated firewall blocks from same IP (>=5)
5. User targeted from many IPs (>=3) -- coordinated/distributed attack
6. Abnormal service restart frequency (>=5 restarts)
7. High-speed attack progression (>=10 events in <60s)

### 2.11 Root Cause and Investigation Insights
**File:** backend/analysis/root_cause.py

All outputs are deterministic and template-driven. No AI/LLM.
- generate_root_cause() -- "WHY did this happen?" paragraph per incident type
- generate_executive_summary() -- management-level paragraph
- generate_technical_summary() -- single-line technical detail string
- generate_attack_narrative() -- chronological list from incident.timeline
- generate_affected_assets() -- list of IPs, users, services
- generate_mitre_summary() -- maps MITRE technique IDs to human-readable names

### 2.12 WebSocket
**File:** backend/websocket/manager.py

ConnectionManager broadcasts Pydantic model dumps as JSON.

| Event | Trigger |
|-------|---------|
| new_logs | New log entries (last 50 per batch) |
| new_alert | Each new alert |
| new_incident | Each new or updated incident |
| stats_update | After any batch with new entries |
| evidence_created | After evidence collected for an incident |
| observation_promoted | When observation auto-promotes |

Frontend hook: useWebSocket auto-reconnects every 3s, heartbeat ping every 30s.

### 2.13 Dashboard
Page: frontend/src/pages/Dashboard.tsx -- 8 sections top-to-bottom:
1. ActiveThreatCenter -- active CRITICAL/HIGH incidents
2. DashboardIntel -- SOC intelligence (calls /dashboard-intelligence)
3. ThreatSummary -- metric cards
4. MonitoringSources -- monitoring folder, active files, simulation status
5. PipelineVisualizer + MonitoringStatusWidget -- 2/3:1/3 grid
6. LogStream + IncidentList -- 2/3:1/3 grid
7. InvestigationPanel -- quick investigation workspace
8. DashboardCharts -- analytics charts

### 2.14 Monitoring
Service: backend/services/monitoring.py

MonitorManager wraps LogWatcher with:
- Session lifecycle tracking (MonitoringSession -- events/alerts/incidents/EPS)
- Session history (list of completed sessions)
- Start/stop/pause/resume operations
- Auto-start on boot if log files exist in sample_logs/

LogWatcher (backend/services/log_watcher.py):
- Polls every 200ms (LOG_TAIL_POLL_INTERVAL)
- Per-file WatchedFile state: path, offset, lines_processed, last_size
- Discovers new files every ~5 polls (~1 second)
- Log rotation detection (file shrinks below current offset)
- Monitors .log files + named files: syslog, auth.log, kern.log, messages, nginx_access.log, apache_access.log

### 2.15 Simulation
Service: backend/services/simulator.py
**IMPORTANT: Development/demo tool only. Not a production feature.**

SimulatorEngine writes realistic log lines to backend/sample_logs/simulation.log.
LogWatcher picks them up automatically -- no special code path.

10 attack scenarios:
- Authentication: ssh_brute_force, ssh_brute_then_login, privilege_escalation
- Web: web_recon, directory_traversal, sql_injection
- Network: firewall_deny_burst, port_scan
- System: repeated_service_failure, suspicious_cron

Modes: one-shot batch or continuous loop.
Speeds: slow=2s, normal=0.8s, fast=0.2s, very_fast=0.05s between scenarios.

### 2.16 Reports
Backend: backend/reports/exporter.py | Frontend: frontend/src/pages/Reports.tsx
- JSON: full structured dump (stats, incidents, alerts, log count)
- CSV: all log entries in tabular format
- PDF: incident summary (requires optional fpdf2; returns HTTP 501 if absent)

---

## 3. Folder Structure

```
d:\syslog-a\
|-- PROJECT_CONTEXT.md          # OLD -- outdated, superseded by v2
|-- PROJECT_CONTEXT_v2.md       # THIS FILE -- current master handoff document
|
|-- backend/
|   |-- main.py                 # FastAPI app, lifespan, CORS, route mounting
|   |-- config.py               # All constants: thresholds, buffers, paths, CORS
|   |-- requirements.txt        # Python dependencies
|   |-- sample_logs/            # Watched folder (auto-created); simulation.log written here
|   |-- exports/                # JSON/CSV/PDF exports (auto-created)
|   |-- api/
|   |   +-- routes.py           # All 37 REST endpoints (666 lines)
|   |-- models/
|   |   +-- events.py           # All Pydantic models (LogEntry, Alert, Incident 40+ fields,
|   |                           #   Evidence, Observation, DashboardStats, MonitoringStatus)
|   |-- parser/
|   |   +-- log_parser.py       # Raw line -> LogEntry; handles syslog/Apache/UFW/systemd
|   |-- detection/
|   |   |-- rules.py            # 15 DetectionRule definitions (R001-R015)
|   |   +-- threat_engine.py    # Stateful rule evaluator, sliding-window checks
|   |-- correlation/
|   |   +-- correlation_engine.py  # 5 sliding-window correlation scenarios -> Incident
|   |-- analysis/
|   |   |-- incident_builder.py       # Orchestrates 14-step incident enrichment
|   |   |-- confidence.py             # V1 confidence score (4 weighted factors)
|   |   |-- reasoning.py              # Template-based reasoning + recommendations
|   |   |-- attack_chain.py           # 3 kill-chain patterns; stage tracking
|   |   |-- threat_scorer.py          # V2 threat score (10 factors); SOC priority
|   |   |-- behaviour.py              # 7 behavioural pattern detectors
|   |   |-- root_cause.py             # Root cause + exec/tech summaries + narrative
|   |   |-- smart_recommendations.py  # Structured recommendations (priority/reason/impact)
|   |   |-- evidence_engine.py        # Evidence + Observation creation; auto-promotion
|   |   |-- evidence_graph.py         # In-memory graph: Event->Alert->Incident nodes
|   |   |-- ioc_extractor.py          # Regex IOC extraction (11 types)
|   |   |-- ioc_relationship.py       # IOC relationship graph with confidence scoring
|   |   +-- incident_merger.py        # Deduplication + false positive reduction
|   |-- services/
|   |   |-- pipeline.py        # Central orchestrator (356 lines)
|   |   |-- monitoring.py      # MonitorManager + MonitoringSession
|   |   |-- log_watcher.py     # Multi-file LogWatcher (polling, 297 lines)
|   |   +-- simulator.py       # Attack simulation engine (509 lines)
|   |-- reports/
|   |   +-- exporter.py        # JSON, CSV, PDF export
|   |-- websocket/
|   |   +-- manager.py         # WebSocket ConnectionManager
|   +-- utils/                 # Helpers (currently minimal)
|
+-- frontend/
    |-- package.json
    |-- tsconfig.json
    |-- vite.config.ts
    +-- src/
        |-- App.tsx              # BrowserRouter + providers + route declarations
        |-- main.tsx             # React root mount
        |-- index.css            # Tailwind v4 @theme + dark mode + animations
        |-- pages/
        |   |-- Dashboard.tsx    # Main SOC dashboard (8 sections)
        |   |-- Incidents.tsx    # Incident list + IncidentDetail (same file, 497 lines)
        |   |-- Logs.tsx         # Paginated log browser with filters
        |   |-- Simulator.tsx    # Attack simulator controls
        |   |-- Reports.tsx      # Export buttons
        |   +-- Settings.tsx     # Config display + clear button
        |-- components/
        |   |-- charts/
        |   |   +-- DashboardCharts.tsx         # Severity, time, rule, threat charts
        |   |-- dashboard/
        |   |   |-- ActiveThreatCenter.tsx      # Priority-ordered active high/critical incidents
        |   |   |-- DashboardIntel.tsx          # SOC intelligence summary
        |   |   |-- IncidentList.tsx            # Compact incident list widget
        |   |   |-- InvestigationPanel.tsx      # Inline investigation workspace
        |   |   |-- LogStream.tsx               # Live scrolling log feed
        |   |   +-- ThreatSummary.tsx           # Metric cards
        |   |-- investigation/
        |   |   |-- DetectionExplanation.tsx    # Matched conditions display
        |   |   |-- IOCPanel.tsx                # IOC table
        |   |   +-- InvestigationWorkspace.tsx  # AttackChainViz, ThreatScoreBreakdown,
        |   |                                   #   BehaviouralPanel, RootCauseWorkspace,
        |   |                                   #   SmartRecommendationsPanel
        |   |-- layout/
        |   |   |-- Header.tsx         # Title, WS status, theme placeholder
        |   |   |-- Sidebar.tsx        # Navigation links
        |   |   +-- Layout.tsx         # ThreatBanner + Outlet + Notifications
        |   |-- monitoring/
        |   |   |-- MonitoringSources.tsx    # File list, session info
        |   |   |-- MonitoringStatus.tsx     # Start/stop/pause/resume controls
        |   |   +-- PipelineVisualizer.tsx   # Animated pipeline flow diagram
        |   |-- notifications/
        |   |   |-- NotificationToast.tsx    # Slide-in toasts
        |   |   +-- ThreatBanner.tsx         # CRITICAL incident banner
        |   +-- simulation/
        |       +-- SimulationSummary.tsx    # Post-simulation stats
        |-- context/
        |   |-- AppContext.tsx           # useReducer state + WS dispatch
        |   |-- NotificationContext.tsx  # Toast queue
        |   +-- ThemeContext.tsx         # Dark/light toggle + localStorage
        |-- hooks/
        |   +-- useWebSocket.ts    # Auto-reconnect (3s), heartbeat (30s)
        |-- services/
        |   +-- api.ts             # 35 typed REST API methods
        |-- types/
        |   +-- index.ts           # TS interfaces mirroring all Pydantic models (362 lines)
        +-- utils/
            +-- formatters.ts      # formatTime, formatDateTime, relativeTime, formatDuration
```

---

## 4. Technology Stack

### Frontend
| Technology | Role |
|-----------|------|
| React 18 | UI framework |
| Vite 5+ | Build tool + dev server |
| TypeScript 5+ | Static typing |
| Tailwind CSS v4 | Styling via @theme custom properties |
| React Router v6 | Client-side routing |
| Lucide React | Icon library |

### Backend
| Technology | Role |
|-----------|------|
| Python 3.11+ | Runtime |
| FastAPI 0.110+ | API framework |
| Pydantic v2 | Data validation + serialization |
| Uvicorn | ASGI server |
| python-dotenv | Environment variable loading |
| fpdf2 (optional) | PDF export |

### Deployment
| Service | URL | Notes |
|---------|-----|-------|
| Backend | https://syslog-threat-analysis.onrender.com/ | Render free tier -- sleeps after inactivity |
| Frontend | Netlify | Static deployment |
| API Docs | /docs | FastAPI Swagger UI |

### Environment Variables
| Variable | Side | Purpose |
|----------|------|---------|
| VITE_API_BASE_URL | Frontend | Backend base URL (omit for relative /api) |
| PORT | Backend | Server port (default: 8000) |
| CORS_ORIGINS | Backend | Comma-separated additional allowed origins |

---

## 5. Current Features (Complete Inventory)

### Log Ingestion and Monitoring
- Multi-file simultaneous monitoring of an entire folder
- Auto-discovery of new log files while monitoring is active
- Per-file byte-offset tracking (survives pause/resume)
- Log rotation detection
- Polling-based (200ms) -- PaaS-compatible
- Start/stop/pause/resume monitoring lifecycle
- Session tracking: events processed, alerts generated, incidents generated, EPS

### Log Parsing (4 formats)
- BSD syslog, Apache/Nginx combined log, UFW/iptables firewall block lines, systemd/journald
- Fields: timestamp, hostname, service, process, source_ip, username, message, event_type, severity, log_format

### Threat Detection (15 rules, R001-R015)
- SSH brute force, invalid user, root login, successful login after failures
- Privilege escalation (sudo/su)
- SQL injection, directory traversal, suspicious user agent, excessive 404s
- Firewall blocks, kernel panic, disk full, service crash, multiple auth failures

### Incident Correlation (5 scenarios)
- Brute Force Attack, Account Compromise, Web Reconnaissance, Privilege Escalation Sequence, Repeated Service Failure

### Incident Enrichment (14-step pipeline per incident)
1. Confidence score (V1, 4 weighted factors)
2. Risk level (CRITICAL/HIGH/MEDIUM/LOW)
3. Human-readable reasoning paragraph
4. Standard recommendations list
5. Attack chain detection (chain_id, stage, progress %)
6. Threat score V2 (0-100, 10 factors)
7. Behavioural findings (7 patterns)
8. Root cause paragraph
9. Smart recommendations (action, priority, reason, impact)
10. Executive summary
11. Technical summary
12. Attack narrative (chronological from timeline)
13. Affected assets list
14. MITRE ATT&CK summary

### Evidence Intelligence
- Structured Evidence objects per incident with matched conditions
- IOC extraction (11 types via regex)
- Sub-threshold Observation objects with auto-promotion
- EvidenceGraph (in-memory entity relationship graph)

### IOC Relationship Graph
- IP, username, hostname, service tracking with cross-linking
- Confidence scoring; top-N by confidence; per-incident IOC list

### Attack Chain Intelligence
- 3 kill-chain patterns with stage tracking
- Progress percentage and stages remaining; estimated objective

### SOC Queue and Priority
- All active incidents ranked by composite threat score
- Integer priority field (1 = highest); exposed via /dashboard-intelligence

### Incident Merging and False Positive Reduction
- Deduplication: same attacker + victim within 5 minutes -> merge
- Severity elevation on merge; false positive filter on low-confidence single-event incidents

### Real-Time Dashboard
- WebSocket-driven updates (no manual refresh)
- REST API bootstrap on page load
- Active Threat Center, SOC Intelligence, pipeline/monitoring status, live log stream, charts

### Incident Investigation
- Full workspace: attack chain, threat score, behaviour, root cause, recommendations, IOCs, timeline, related logs

### Attack Simulator (dev/demo only)
- 10 attack scenarios in 4 categories; continuous and one-shot modes; 4 speed settings

### Report Export
- JSON, CSV, PDF

### Theme
- Light mode (default) + dark mode CSS infrastructure; persisted to localStorage
- BUG: Toggle button not yet wired in Header

---

## 6. APIs

Base URL: /api/

### Statistics
GET /stats -- Dashboard stats (counts, severity distributions, time series, rule frequency)

### Logs
GET /logs -- Paginated; filter: search, severity, event_type, source_ip, username, service; params: limit, offset
GET /logs/{event_id} -- Single log entry with triggered alerts and rules

### Alerts
GET /alerts -- All alerts; optional ?status=ACTIVE/ACKNOWLEDGED/RESOLVED
POST /alerts/action -- Body: {alert_id, action: "acknowledge" or "resolve"}

### Incidents
GET /incidents -- All incidents sorted by severity (non-merged only)
GET /incidents/{id} -- Full incident with related logs
GET /incidents/{id}/insights -- Full Phase 5.4 intelligence fields

### Monitoring
GET /monitor/status -- Full monitoring status + per-file details
POST /monitor/start -- Body: {file_path?, folder?, from_beginning?}
POST /monitor/stop -- Stop monitoring
POST /monitor/pause -- Pause without ending session
POST /monitor/resume -- Resume paused session
GET /monitor/session -- Current session details
GET /monitor/history -- All completed sessions
GET /monitor/pipeline -- Live pipeline buffer counts

### Simulation
GET /simulation/scenarios -- List available scenarios
POST /simulation/start -- Body: {scenarios?, speed?, target_user?, randomize_ips?}
POST /simulation/stop -- Stop continuous simulation
POST /simulation/reset -- Reset + delete simulation.log
POST /simulation/generate -- One-shot batch; body: {scenarios?, target_user?}
GET /simulation/status -- Current simulation state

### Evidence
GET /evidence -- List evidence; filter: incident_id, rule_id, severity, source_ip, username
GET /evidence/search -- Search by: incident_id, rule_id, severity, source_ip, username, keyword, has_iocs
GET /evidence/by-incident/{id} -- Evidence for a specific incident
GET /evidence/{id} -- Single Evidence object

### Observations
GET /observations -- All observations
GET /observations/{id} -- Single observation
POST /observations/promote -- Body: {observation_id, incident_id?}

### Intelligence
GET /dashboard-intelligence -- SOC intelligence: most dangerous attack, most active attacker, most targeted user/service, top IOCs, attack chains, SOC queue, behaviour findings
GET /attack-chains -- All active attack chains with progress
GET /ioc-relationships -- Top IOCs by confidence; optional ?limit=N
GET /ioc-relationships/{type}/{value} -- IOC detail + related IOCs
GET /ioc-relationships/incident/{id} -- IOCs for a specific incident

### Utility
GET /export/{fmt} -- fmt = json or csv or pdf
POST /clear -- Reset all in-memory data
GET /health, GET /version, GET /ready -- Health/version probes

WebSocket: ws://{host}/ws
Events emitted: new_logs, new_alert, new_incident, stats_update, evidence_created, observation_promoted

---

## 7. Frontend Pages

### / -- Dashboard
Purpose: Primary SOC console. Real-time system overview.
Widgets: ActiveThreatCenter, DashboardIntel, ThreatSummary, MonitoringSources, PipelineVisualizer, MonitoringStatusWidget, LogStream, IncidentList, InvestigationPanel, DashboardCharts.
Status: Complete. Polls monitoring/simulation status every 3s.

### /incidents -- Incident List
Purpose: Browse all detected incidents.
Widgets: Expandable incident cards with severity badge, confidence, risk, MITRE tags, source IP, user, event count.
Status: Complete.

### /incidents/:id -- Incident Detail
Purpose: Full investigation workspace for a single incident.
Widgets: AttackChainViz, ThreatScoreBreakdown, BehaviouralPanel, RootCauseWorkspace, SmartRecommendationsPanel, DetectionExplanation, IOCPanel, attack timeline, related logs table.
Status: Complete. Calls /incidents/{id}/insights.

### /logs -- Log Browser
Purpose: Paginated, filterable view of all parsed log entries.
Widgets: Filter bar (7 filters), log table, log detail modal.
Status: Complete. Not real-time (no WebSocket on this page).

### /simulator -- Attack Simulator
Purpose: Developer/demo tool to generate synthetic attack logs.
Widgets: Scenario checkboxes by category, speed selector, target user input, Start/Stop/Generate/Reset buttons, pipeline stats, simulation summary.
Status: Complete.

### /reports -- Export Reports
Purpose: Export current data.
Widgets: JSON, CSV, PDF export buttons.
Status: Minimal. No filtering, preview, or history.

### /settings -- Settings
Purpose: View configuration; clear all data.
Widgets: Read-only config fields, "Clear All Data" button.
Status: Minimal. All fields are read-only.

---

## 8. Backend Modules

| Module | File | Purpose |
|--------|------|---------|
| App entry | main.py | App creation, lifespan, CORS, health probes |
| Config | config.py | All constants, thresholds, buffer sizes, paths |
| Data models | models/events.py | All Pydantic models |
| Log parser | parser/log_parser.py | Raw line -> LogEntry; 4 log formats |
| Detection rules | detection/rules.py | 15 declarative DetectionRule objects |
| Threat engine | detection/threat_engine.py | Stateful rule evaluation |
| Correlation engine | correlation/correlation_engine.py | 5 sliding-window scenarios -> Incident |
| Pipeline | services/pipeline.py | Orchestrates all engines; buffers; broadcasts |
| Log watcher | services/log_watcher.py | Multi-file polling watcher |
| Monitor manager | services/monitoring.py | Session lifecycle, status aggregation |
| Simulator | services/simulator.py | 10 attack scenarios, 4 speeds |
| Incident builder | analysis/incident_builder.py | 14-step enrichment orchestrator |
| Confidence | analysis/confidence.py | V1 confidence score + risk level |
| Reasoning | analysis/reasoning.py | Template-based reasoning + recommendations |
| Attack chains | analysis/attack_chain.py | 3 kill-chain patterns, stage tracking |
| Threat scorer | analysis/threat_scorer.py | V2 score (10 factors) + SOC priority |
| Behaviour | analysis/behaviour.py | 7 behavioural pattern detectors |
| Root cause | analysis/root_cause.py | Root cause + summaries + narrative + assets + MITRE |
| Smart recs | analysis/smart_recommendations.py | Structured recommendations |
| Evidence engine | analysis/evidence_engine.py | Evidence + Observation creation |
| Evidence graph | analysis/evidence_graph.py | In-memory entity relationship graph |
| IOC extractor | analysis/ioc_extractor.py | Regex IOC extraction (11 types) |
| IOC engine | analysis/ioc_relationship.py | IOC relationship graph + confidence |
| Incident merger | analysis/incident_merger.py | Deduplication + false positive filter |
| REST API | api/routes.py | All 37 REST endpoints (666 lines) |
| WebSocket | websocket/manager.py | Connection management + broadcast |
| Exporter | reports/exporter.py | JSON, CSV, PDF export |

---

## 9. Completed Roadmap

### Phase 1 -- Foundation
FastAPI backend scaffold, basic REST endpoints, syslog parser, 5-8 initial detection rules, React + Vite + Tailwind frontend scaffold, basic dashboard with log table and alert list.

### Phase 2 -- Detection and Correlation
Expanded to 15 detection rules with MITRE ATT&CK mappings, 5-scenario correlation engine, incident creation and management, WebSocket integration for real-time updates.

### Phase 3 -- Multi-File Monitoring
LogWatcher redesigned for simultaneous multi-file monitoring with per-file offset tracking, auto-discovery of new files, log rotation detection, MonitorManager session lifecycle. Added Apache, UFW, systemd log format support.

### Phase 4 -- Evidence Intelligence (ESIE)
Structured Evidence objects with per-rule matched conditions, IOC extraction (11 types), Observation system for sub-threshold detections with auto-promotion, EvidenceGraph for entity relationships, IOCRelationshipEngine with cross-linking and confidence scoring.

### Phase 5.1 to 5.3 -- Frontend SOC Experience
ActiveThreatCenter, live notifications (toasts + critical banner), enhanced incident cards, DetectionExplanation, IOCPanel, DashboardIntel, PipelineVisualizer, MonitoringStatus, SimulationSummary, ThemeContext + CSS variable infrastructure.

### Phase 5.4 -- Advanced Intelligence Engine
AttackChainDetector (3 kill-chain patterns), Threat Scoring V2 (10 factors), BehaviourAnalyzer (7 patterns), root cause engine, smart recommendations, investigation insights (executive summary, technical summary, attack narrative, affected assets, MITRE summary), IncidentMerger, SOC queue priority ranking. All fields exposed on Incident model and consumed by frontend.

---

## 10. Remaining Roadmap

### Phase 5.5 -- SOC Investigation Workspace (not started)
Objective: Create a professional, fully realized SOC Investigation Workspace that exposes all existing backend intelligence through polished, actionable UI.

Planned scope:
- Attack Chain Visualization -- graphical kill-chain stage view with progress indicator
- SOC Queue -- analyst work queue ordered by threat priority score
- Behaviour Intelligence Panel -- global behavioural findings across all data
- Threat Score Breakdown -- per-factor bar chart visualization
- Root Cause Workspace -- root cause + affected assets in structured layout
- Smart Recommendations Panel -- actionable items with priority badges
- IOC Explorer -- searchable, filterable IOC browser
- Incident Lifecycle Management -- status transitions (ACTIVE -> INVESTIGATING -> RESOLVED -> CLOSED)
- Notification Aggregation -- consolidated notification history
- Dashboard Intelligence -- enhanced layout for existing intelligence data
- Performance improvements -- optimize WebSocket handling for high-volume scenarios
- Investigation Navigation -- keyboard shortcuts and quick-navigation between incidents

### Phase 6 -- Productization (not started)
Objective: Replace the Simulator-first workflow with production-grade Data Sources. The Simulator is a development/demo tool and must NOT be presented as a production feature.

Planned scope:
- Data Sources Page replacing current Simulator page as primary workflow entry point
- Live Monitoring mode -- select and monitor any folder on the server
- Uploaded Log Investigation -- upload a log file for batch processing and analysis
- Simulation Engine -- moved to "Developer Mode" or hidden tab; no longer primary UX
- Future collectors (architecture/placeholder): Syslog UDP listener, Filebeat receiver, Wazuh agent, Fluent Bit input, Windows Event Forwarding

### Phase 7 -- Project Finalization (not started)
Objective: Prepare the project for submission, public demonstration, and handoff.

Planned deliverables:
- Complete README with setup, usage, architecture overview
- Architecture diagrams (system diagram, data flow, component diagram)
- Deployment documentation (Render + Netlify)
- Performance validation (throughput testing with simulator)
- GitHub cleanup (branch hygiene, commit messages, tags)
- Presentation materials for internship submission

---

## 11. Important Design Decisions

**Why In-Memory State?**
Deliberately chosen for Phases 1-5 to eliminate database complexity and focus on the intelligence pipeline. The architecture is ready for database integration (each stateful class has clear() and bounded buffers).

**Why Polling Instead of File System Events?**
LogWatcher polls every 200ms instead of using inotify or ReadDirectoryChangesW. Chosen for PaaS compatibility -- Render, Railway, and Heroku may not expose OS-level file events.

**Why No LLM or ML?**
All reasoning, recommendations, root cause, and intelligence are deterministic and template-driven. This ensures explainability (every output traces to specific code logic), no API keys required (works fully offline), and correctness (deterministic systems do not hallucinate).

**Why Backend-Authoritative Intelligence?**
The backend computes everything: confidence, risk, reasoning, attack chains, threat scores, recommendations, root cause, executive summaries. The frontend only renders what it receives. This prevents business logic from leaking into the UI layer.

**Simulator is a Development Tool.**
The simulator exists because enterprise log infrastructure (Syslog servers, Filebeat, Wazuh) is unavailable in development. It is NOT a production feature. Phase 6 replaces the Simulator page with a Data Sources page.

**TypeScript Interfaces Mirror Pydantic Models Exactly.**
frontend/src/types/index.ts mirrors backend/models/events.py field-for-field. Any change to a Pydantic model must be reflected in the TypeScript interface immediately.

**Frontend State Architecture.**
AppContext uses useReducer because the state shape is simple and well-defined. WebSocket pushes deltas; REST API provides initial load. Frontend caps: logs at 500, alerts at 200.

**Two Separate Scoring Systems.**
- Confidence (V1): "how sure are we this is a real incident?" (4 factors)
- Threat Score (V2): "how dangerous is this incident?" (10 factors)
Both are displayed for different analyst purposes.

---

## 12. Known Limitations

### Current Limitations
- In-memory only. All state lost on backend restart. On Render free tier, backend sleeps after 15 minutes.
- No authentication. All API endpoints publicly accessible.
- Single process. No horizontal scaling.
- No rule management API. Rules hardcoded in rules.py.
- Settings are read-only. Settings page displays config but cannot modify it.
- Observations not visible in UI. Full Observations API exists but no frontend panel.
- No dedicated Alerts page. Alerts only visible as counts; no browse/acknowledge/resolve UI.
- Dark mode toggle not wired. ThemeContext complete; Header button is a placeholder only.

### Production Limitations
- Render free tier restarts -> lost state on cold start
- No TLS on WebSocket in development
- PDF export requires optional fpdf2; returns 501 if absent
- Log files must be readable by the backend OS process

### Testing Limitations
- No automated test suite (no pytest, no Vitest)
- All validation is manual via the attack simulator
- No load testing or stress testing performed

---

## 13. Known Bugs

### Bug 1: R009 Port Scan -- Dead Rule
**File:** backend/detection/threat_engine.py
**Description:** Rule R009 is declared in rules.py but no _check_port_scan() method exists in threat_engine.py. The rule never fires.
**Impact:** Port scan scenarios generate R010 (Firewall Block) alerts only. No Port Scan incident is ever created.
**Fix:** Add _check_port_scan() with sliding-window unique-port-per-IP logic (threshold: 20 ports in 30s from config.py). Add a corresponding correlation scenario in correlation_engine.py.

### Bug 2: Attack Chain persistence Stage Unreachable
**File:** backend/analysis/attack_chain.py
**Description:** The credential_compromise chain defines 5 stages including persistence. No rule or incident type maps to persistence in rule_stage_map or type_stage_map.
**Impact:** The chain can reach at most 80% progress. The stages_missing field will always include persistence.
**Fix:** Add a rule (e.g., suspicious cron job, new user creation) that maps to the persistence stage.

### Bug 3: Dark Mode Toggle Not Wired
**File:** frontend/src/components/layout/Header.tsx
**Description:** ThemeContext, useTheme() hook, CSS variables, and localStorage persistence are all implemented. The Header has a placeholder where the toggle button should be but does not call toggleTheme().
**Impact:** Dark mode cannot be activated from the UI.
**Fix:** Add a button with onClick={toggleTheme} in Header.tsx using useTheme().

---

## 14. Future Enhancements (Intentionally Postponed)

- Database persistence (PostgreSQL/SQLite)
- User authentication and RBAC
- Runtime rule management (add/edit/disable detection rules via API + UI)
- Real log collectors (Syslog UDP, Filebeat, Wazuh, Windows Event Forwarding)
- Horizontal scaling (requires shared state via Redis or database)
- Automated test suite (pytest backend, Vitest frontend)
- Alert lifecycle management (bulk acknowledge/resolve, alert aging/expiry)
- Scheduled reports (recurring export of incident summaries)
- Custom dashboards (user-configurable widget layouts)
- Historical log replay (re-process a log file for post-incident investigation)
- IP geolocation (attacker origin map visualization)
- SIEM integration (Elasticsearch, Splunk, or Wazuh output adapters)

---

## 15. Current Project State

### What is Complete

**Backend -- 100% functional:**
- All 37 REST API endpoints + 3 health/version probes
- All 6 WebSocket event types
- Full log parsing pipeline (4 formats)
- 14 of 15 detection rules working (R009 broken)
- 5-scenario correlation engine
- 14-step incident enrichment pipeline
- Evidence engine (Evidence + Observation)
- IOC relationship graph
- Attack chain detection (3 chains)
- Threat scoring V2 (10 factors)
- Behavioural analysis (7 patterns)
- Root cause + investigation insights
- Smart recommendations
- Incident merger + false positive reduction
- SOC queue priority ranking
- Dashboard intelligence endpoint
- Attack simulator (10 scenarios, 4 speeds)
- Report export (JSON, CSV, PDF)
- Monitoring session management

**Frontend -- functional with known gaps:**
- All 6 pages render and work
- All 35 API methods implemented and typed
- Real-time WebSocket state integration
- Full incident investigation workspace (Phases 5.1-5.4 components)
- Monitoring controls, pipeline visualizer, simulator controls
- Notification toasts and CRITICAL threat banner
- Dark mode CSS infrastructure (toggle not wired -- Bug 3)

### What Remains

**Immediate bugs to fix:**
1. R009 Port Scan check method missing in threat_engine.py (Bug 1)
2. Dark mode toggle button missing in Header.tsx (Bug 3)
3. Observations UI missing (no page or panel in frontend)
4. Alerts page missing (no browse/manage UI)

**Planned development phases:**
- Phase 5.5 -- SOC Investigation Workspace
- Phase 6 -- Productization (Data Sources page, real log collectors)
- Phase 7 -- Finalization (README, diagrams, deployment docs, GitHub cleanup, submission)

---

*End of PROJECT_CONTEXT_v2.md*
*Generated from full codebase read on 2026-07-22.*
*Do not edit manually -- regenerate from source when project state changes significantly.*
