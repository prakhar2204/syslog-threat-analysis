/* SysLog Threat Analysis — Dashboard Incident List (Rich Cards) */

import type { Incident, Severity } from '../../types';
import { formatTime, relativeTime, formatDuration } from '../../utils/formatters';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, Target, User, Clock, Hash, Activity } from 'lucide-react';

interface Props {
  incidents: Incident[];
}

function sevBadge(s: Severity): string {
  return {
    CRITICAL: 'bg-severity-critical text-white',
    HIGH: 'bg-severity-high text-white',
    MEDIUM: 'bg-severity-medium text-black',
    LOW: 'bg-severity-low text-white',
    INFO: 'bg-severity-info text-white',
  }[s];
}

function sevBorder(s: Severity): string {
  return {
    CRITICAL: 'border-l-severity-critical',
    HIGH: 'border-l-severity-high',
    MEDIUM: 'border-l-severity-medium',
    LOW: 'border-l-severity-low',
    INFO: 'border-l-severity-info',
  }[s];
}

export default function IncidentList({ incidents }: Props) {
  const nav = useNavigate();

  return (
    <div className="bg-bg-card border border-border rounded">
      <div className="px-3 py-2 border-b border-border flex items-center justify-between">
        <span className="text-xs font-semibold text-text-primary">Recent Incidents</span>
        <span className="text-[9px] text-text-secondary">{incidents.length} total</span>
      </div>
      {incidents.length === 0 ? (
        <div className="p-4 text-center text-xs text-text-secondary">No incidents detected.</div>
      ) : (
        <div className="divide-y divide-border">
          {incidents.slice(0, 8).map((inc) => (
            <div
              key={inc.incident_id}
              className={`px-3 py-2.5 border-l-3 ${sevBorder(inc.severity)} hover:bg-bg-main cursor-pointer transition-colors`}
              onClick={() => nav(`/incidents/${inc.incident_id}`)}
            >
              {/* Row 1: Type + severity + confidence */}
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${sevBadge(inc.severity)}`}>
                  {inc.severity}
                </span>
                <span className="text-[11px] font-semibold text-text-primary flex-1 truncate">{inc.incident_type}</span>
                <span className="text-[10px] text-primary font-semibold">{inc.confidence}%</span>
              </div>

              {/* Row 2: Key intel */}
              <div className="flex items-center gap-3 text-[9px] text-text-secondary mb-1">
                <span className="flex items-center gap-0.5">
                  <Target size={8} /> <span className="font-mono">{inc.source_ips[0] || '—'}</span>
                </span>
                <span className="flex items-center gap-0.5">
                  <User size={8} /> {inc.target_user || '—'}
                </span>
                <span className="flex items-center gap-0.5">
                  <Hash size={8} /> {inc.total_events}
                </span>
                <span className="flex items-center gap-0.5">
                  <Activity size={8} /> {inc.related_alert_ids.length}
                </span>
              </div>

              {/* Row 3: Time + MITRE + Investigate */}
              <div className="flex items-center gap-2 text-[9px] text-text-secondary">
                <span className="flex items-center gap-0.5">
                  <Clock size={8} /> {formatTime(inc.first_seen)}
                </span>
                <span>{formatDuration(inc.first_seen, inc.last_seen)}</span>
                {inc.mitre_techniques.length > 0 && (
                  <span className="text-primary font-mono">{inc.mitre_techniques[0]}</span>
                )}
                <span className="text-[8px] px-1 py-0.5 rounded bg-bg-main">{inc.risk}</span>
                <button
                  onClick={(e) => { e.stopPropagation(); nav(`/incidents/${inc.incident_id}`); }}
                  className="ml-auto flex items-center gap-0.5 text-primary hover:underline font-medium"
                >
                  Investigate <ArrowRight size={8} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
