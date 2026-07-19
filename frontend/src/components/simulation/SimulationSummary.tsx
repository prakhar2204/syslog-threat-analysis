/* SysLog Threat Analysis — Simulation Summary */

import { BarChart3, Clock, Zap, AlertTriangle, ShieldAlert, Fingerprint, Search, Activity, CheckCircle } from 'lucide-react';
import type { SimulationStatus, PipelineStats } from '../../types';

interface Props {
  status: SimulationStatus;
  pipeline: PipelineStats | null;
}

export default function SimulationSummary({ status, pipeline }: Props) {
  // Only show when simulation has completed (not active but has generated events)
  if (status.active || status.events_generated === 0) return null;

  const metrics = [
    { label: 'Duration', value: status.elapsed_seconds > 0 ? `${status.elapsed_seconds.toFixed(1)}s` : '—', icon: Clock, color: 'text-primary' },
    { label: 'Events Generated', value: status.events_generated.toLocaleString(), icon: Zap, color: 'text-severity-medium' },
    { label: 'Parsed', value: pipeline?.events_parsed?.toLocaleString() || '—', icon: Activity, color: 'text-primary' },
    { label: 'Rules Triggered', value: pipeline?.rules_triggered?.toLocaleString() || '—', icon: AlertTriangle, color: 'text-severity-high' },
    { label: 'Alerts', value: pipeline?.alerts_generated?.toLocaleString() || '—', icon: ShieldAlert, color: 'text-severity-critical' },
    { label: 'Incidents', value: pipeline?.incidents_generated?.toLocaleString() || '—', icon: Search, color: 'text-severity-critical' },
    { label: 'Scenarios Run', value: String(status.scenarios?.length || 0), icon: BarChart3, color: 'text-primary' },
    { label: 'Speed', value: status.speed, icon: Fingerprint, color: 'text-text-secondary' },
  ];

  return (
    <div className="bg-bg-card border border-border rounded p-4">
      <div className="flex items-center gap-2 mb-3">
        <CheckCircle size={14} className="text-severity-info" />
        <span className="text-xs font-semibold text-text-primary">Simulation Complete</span>
      </div>
      <div className="grid grid-cols-4 gap-2">
        {metrics.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-bg-main rounded p-2 border border-border">
            <div className="flex items-center gap-1 text-[9px] text-text-secondary mb-0.5">
              <Icon size={9} className={color} /> {label}
            </div>
            <div className="text-sm font-semibold text-text-primary">{value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
