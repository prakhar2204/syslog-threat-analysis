/* SysLog Threat Analysis - TypeScript Interfaces */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type AlertStatus = 'ACTIVE' | 'ACKNOWLEDGED' | 'RESOLVED';
export type IncidentStatus = 'ACTIVE' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';

export interface LogEntry {
  event_id: string;
  timestamp: string;
  hostname: string;
  source_ip: string | null;
  destination_ip: string | null;
  username: string | null;
  service: string;
  process: string;
  event_type: string;
  message: string;
  raw_log: string;
  severity: Severity;
  log_format: string;
}

export interface Alert {
  alert_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  source_ip: string | null;
  username: string | null;
  description: string;
  matched_event_id: string;
  timestamp: string;
  status: AlertStatus;
  mitre: string | null;
  event_count: number;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  description: string;
  severity: Severity;
}

export interface Incident {
  incident_id: string;
  incident_type: string;
  severity: Severity;
  confidence: number;
  risk: string;
  status: IncidentStatus;
  source_ips: string[];
  target_user: string | null;
  first_seen: string;
  last_seen: string;
  total_events: number;
  description: string;
  reasoning: string;
  recommendations: string[];
  timeline: TimelineEvent[];
  related_alert_ids: string[];
  related_event_ids: string[];
  triggered_rules: string[];
  mitre_techniques: string[];
  correlation_explanation: string;
  related_logs?: LogEntry[];
}

export interface DashboardStats {
  total_logs: number;
  info_events: number;
  warning_events: number;
  high_events: number;
  critical_events: number;
  total_alerts: number;
  active_alerts: number;
  total_incidents: number;
  active_incidents: number;
  top_source_ips: { ip: string; count: number }[];
  top_event_types: { type: string; count: number }[];
  severity_distribution: { severity: string; count: number }[];
  logs_over_time: { time: string; count: number }[];
  rule_frequency: { rule_id: string; rule_name: string; count: number }[];
  threat_trend: { time: string; count: number }[];
}

export interface WatchedFileStatus {
  path: string;
  filename: string;
  offset: number;
  lines_processed: number;
  last_size: number;
  active: boolean;
}

export interface MonitoringStatus {
  active: boolean;
  paused: boolean;
  mode: string | null;
  folder: string | null;
  files_monitored: number;
  active_files: WatchedFileStatus[];
  lines_processed: number;
  watcher_uptime_seconds: number;
  events_per_second: number;
  last_event_time: string | null;
  session: MonitorSession | null;
  pipeline: PipelineStats;
}

export interface MonitorSession {
  session_id: string;
  source_type: string;
  source_path: string;
  status: string;
  start_time: string;
  end_time: string | null;
  duration_seconds: number;
  events_processed: number;
  alerts_generated: number;
  incidents_generated: number;
  events_per_second: number;
}

export interface PipelineStats {
  events_in: number;
  events_parsed: number;
  rules_triggered: number;
  alerts_generated: number;
  incidents_generated: number;
  // Also used as pipeline buffer counts
  logs_buffered?: number;
  alerts_buffered?: number;
  incidents_buffered?: number;
}

export interface SimulationStatus {
  active: boolean;
  speed: string;
  scenarios: string[];
  target_user: string;
  randomize_ips: boolean;
  events_generated: number;
  elapsed_seconds: number;
  sim_file: string;
}

export interface SimScenario {
  id: string;
  name: string;
  description: string;
  category: string;
}

export interface MatchedCondition {
  condition: string;
  matched: boolean;
  value: string;
}

export interface ExtractedIOC {
  ioc_type: string;
  value: string;
  source_event_id: string;
}

export interface RawLogRef {
  event_id: string;
  raw_log: string;
  timestamp: string;
  hostname: string;
  source_ip: string | null;
  destination_ip: string | null;
  username: string | null;
  service: string;
  process: string;
  event_type: string;
  message: string;
  severity: string;
  detection_rule_ids: string[];
}

export interface Evidence {
  evidence_id: string;
  incident_id: string | null;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  matched_conditions: MatchedCondition[];
  source_ips: string[];
  destination_ips: string[];
  hostnames: string[];
  usernames: string[];
  processes: string[];
  services: string[];
  protocols: string[];
  ports: number[];
  first_seen: string;
  last_seen: string;
  related_event_ids: string[];
  related_alert_ids: string[];
  raw_log_refs: RawLogRef[];
  extracted_iocs: ExtractedIOC[];
  event_count: number;
  unique_source_count: number;
  unique_dest_count: number;
  collection_confidence: number;
}

export type ObservationStatus = 'OPEN' | 'PROMOTED' | 'DISMISSED';

export interface Observation {
  observation_id: string;
  status: ObservationStatus;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  matched_conditions: MatchedCondition[];
  source_ips: string[];
  usernames: string[];
  services: string[];
  hostnames: string[];
  first_seen: string;
  last_seen: string;
  related_event_ids: string[];
  related_alert_ids: string[];
  raw_log_refs: RawLogRef[];
  extracted_iocs: ExtractedIOC[];
  event_count: number;
  unique_source_count: number;
  collection_confidence: number;
  promoted: boolean;
  promoted_to_incident_id: string | null;
}

export interface LogFile {
  name: string;
  path: string;
  size_bytes: number;
}

export interface PaginatedLogs {
  items: LogEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface WSMessage {
  type: 'new_logs' | 'new_alert' | 'new_incident' | 'stats_update' | 'status' | 'evidence_created' | 'observation_promoted';
  data: unknown;
  timestamp: string;
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  description: string;
  severity: Severity;
  mitre: string | null;
  recommendation: string;
}

export interface LogDetail {
  entry: LogEntry;
  triggered_alerts: Alert[];
  triggered_rules: DetectionRule[];
}
