/* SysLog Threat Analysis — Active Threat Center */

import { useNavigate } from 'react-router-dom';
import { ShieldAlert, ArrowRight, Target, User, Server, Clock, Hash } from 'lucide-react';
import type { Incident, Severity } from '../../types';
import { formatTime, relativeTime, formatDuration } from '../../utils/formatters';

interface Props {
  incidents: Incident[];
}

function sevColor(s: Severity): string {
  const m: Record<Severity, string> = {
    CRITICAL: 'border-severity-critical',
    HIGH: 'border-severity-high',
    MEDIUM: 'border-severity-medium',
    LOW: 'border-severity-low',
    INFO: 'border-severity-info',
  };
  return m[s];
}

function sevBg(s: Severity): string {
  const m: Record<Severity, string> = {
    CRITICAL: 'bg-severity-critical text-white',
    HIGH: 'bg-severity-high text-white',
    MEDIUM: 'bg-severity-medium text-black',
    LOW: 'bg-severity-low text-white',
    INFO: 'bg-severity-info text-white',
  };
  return m[s];
}

export default function ActiveThreatCenter({ incidents }: Props) {
  const nav = useNavigate();
  const active = incidents.filter(i => i.status === 'ACTIVE').slice(0, 8);

  if (active.length === 0) {
    return (
      <div className="bg-bg-card border border-border rounded p-4">
        <div className="flex items-center gap-2 mb-2">
          <ShieldAlert size={14} className="text-primary" />
          <span className="text-xs font-semibold text-text-primary">Active Threat Center</span>
        </div>
        <div className="text-xs text-text-secondary text-center py-4">No active threats detected. System is secure.</div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <ShieldAlert size={14} className="text-severity-critical" />
        <span className="text-xs font-semibold text-text-primary">Active Threat Center</span>
        <span className="text-[10px] text-text-secondary ml-auto">{active.length} active threat{active.length > 1 ? 's' : ''}</span>
      </div>
      <div className="grid grid-cols-2 gap-2">
        {active.map(inc => (
          <div
            key={inc.incident_id}
            className={`bg-bg-card border-l-4 ${sevColor(inc.severity)} border border-border rounded p-3 hover:shadow-md cursor-pointer transition-shadow`}
            onClick={() => nav(`/incidents/${inc.incident_id}`)}
          >
            {/* Row 1: Type + badges */}
            <div className="flex items-center gap-2 mb-2">
              <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${sevBg(inc.severity)}`}>
                {inc.severity}
              </span>
              <span className="text-xs font-semibold text-text-primary flex-1 truncate">{inc.incident_type}</span>
              <span className="text-[10px] text-primary font-semibold">{inc.confidence}%</span>
            </div>

            {/* Row 2: Key fields */}
            <div className="grid grid-cols-3 gap-x-3 gap-y-1 text-[10px] mb-2">
              <div className="flex items-center gap-1 text-text-secondary">
                <Target size={9} className="shrink-0" />
                <span className="truncate font-mono">{inc.source_ips[0] || '—'}</span>
              </div>
              <div className="flex items-center gap-1 text-text-secondary">
                <User size={9} className="shrink-0" />
                <span className="truncate">{inc.target_user || '—'}</span>
              </div>
              <div className="flex items-center gap-1 text-text-secondary">
                <Server size={9} className="shrink-0" />
                <span className="truncate">{inc.triggered_rules[0] || '—'}</span>
              </div>
            </div>

            {/* Row 3: Meta */}
            <div className="flex items-center gap-3 text-[9px] text-text-secondary">
              <span className="flex items-center gap-0.5">
                <Hash size={8} /> {inc.total_events} events
              </span>
              <span className="flex items-center gap-0.5">
                <Clock size={8} /> {formatTime(inc.first_seen)}
              </span>
              {inc.mitre_techniques.length > 0 && (
                <span className="text-primary font-mono">{inc.mitre_techniques[0]}</span>
              )}
              <span className="text-text-secondary">{inc.risk}</span>
              <span className="ml-auto text-text-secondary">{relativeTime(inc.last_seen)}</span>
            </div>

            {/* Investigate button */}
            <div className="mt-2 pt-2 border-t border-border flex items-center justify-between">
              <span className="text-[9px] text-text-secondary">Duration: {formatDuration(inc.first_seen, inc.last_seen)}</span>
              <button
                onClick={(e) => { e.stopPropagation(); nav(`/incidents/${inc.incident_id}`); }}
                className="flex items-center gap-1 text-[10px] text-primary hover:underline font-medium"
              >
                Investigate <ArrowRight size={10} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
