/* SysLog Threat Analysis — Threat Summary */

import {
  ShieldAlert, AlertTriangle, Bell, BellOff, Globe,
  User, Fingerprint, Target, Search, FileText,
} from 'lucide-react';
import { useApp } from '../../context/AppContext';

const METRICS = [
  { key: 'active_threats', label: 'Active Threats', icon: ShieldAlert, color: 'text-severity-critical' },
  { key: 'critical_incidents', label: 'Critical Incidents', icon: AlertTriangle, color: 'text-severity-high' },
  { key: 'open_alerts', label: 'Open Alerts', icon: Bell, color: 'text-severity-medium' },
  { key: 'resolved_alerts', label: 'Resolved', icon: BellOff, color: 'text-severity-info' },
  { key: 'suspicious_ips', label: 'Suspicious IPs', icon: Globe, color: 'text-primary' },
  { key: 'tracked_users', label: 'Tracked Users', icon: User, color: 'text-severity-high' },
  { key: 'extracted_iocs', label: 'IOCs', icon: Fingerprint, color: 'text-severity-critical' },
  { key: 'mitre_techniques', label: 'MITRE Techniques', icon: Target, color: 'text-primary' },
  { key: 'investigations', label: 'Investigations', icon: Search, color: 'text-severity-info' },
  { key: 'evidence_items', label: 'Evidence', icon: FileText, color: 'text-text-secondary' },
] as const;

export default function ThreatSummary() {
  const { state } = useApp();

  // Compute metrics from live state
  const activeThreats = state.incidents.filter(i => i.status === 'ACTIVE').length;
  const criticalIncidents = state.incidents.filter(i => i.severity === 'CRITICAL').length;
  const openAlerts = state.alerts.filter(a => a.status === 'ACTIVE').length;
  const resolvedAlerts = state.alerts.filter(a => a.status === 'RESOLVED').length;

  // Unique suspicious IPs across all incidents
  const suspiciousIps = new Set(state.incidents.flatMap(i => i.source_ips)).size;
  // Unique tracked users
  const trackedUsers = new Set(state.incidents.map(i => i.target_user).filter(Boolean)).size;
  // MITRE techniques across incidents
  const mitreTechniques = new Set(state.incidents.flatMap(i => i.mitre_techniques)).size;

  const values: Record<string, number> = {
    active_threats: activeThreats,
    critical_incidents: criticalIncidents,
    open_alerts: openAlerts,
    resolved_alerts: resolvedAlerts,
    suspicious_ips: suspiciousIps,
    tracked_users: trackedUsers,
    extracted_iocs: state.stats?.total_alerts || 0,
    mitre_techniques: mitreTechniques,
    investigations: state.incidents.length,
    evidence_items: state.stats?.total_incidents || 0,
  };

  return (
    <div className="grid grid-cols-5 gap-2">
      {METRICS.map(({ key, label, icon: Icon, color }) => (
        <div key={key} className="bg-bg-card border border-border rounded px-3 py-2.5">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-text-secondary">{label}</span>
            <Icon size={12} className={color} />
          </div>
          <div className="text-lg font-semibold mt-0.5">
            {values[key]?.toLocaleString() ?? 0}
          </div>
        </div>
      ))}
    </div>
  );
}
