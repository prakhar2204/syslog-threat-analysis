/* SysLog Threat Analysis — TypeScript Interfaces */

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

export interface MonitoringStatus {
  active: boolean;
  file_path: string;
  lines_processed: number;
  last_event_time: string | null;
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
  type: 'new_logs' | 'new_alert' | 'new_incident' | 'stats_update' | 'status';
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
