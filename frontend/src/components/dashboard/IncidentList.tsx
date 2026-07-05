import type { Incident, Severity } from '../../types';
import { formatTime } from '../../utils/formatters';
import { useNavigate } from 'react-router-dom';

interface Props {
  incidents: Incident[];
}

function badgeCls(s: Severity): string {
  const m: Record<Severity, string> = {
    CRITICAL: 'bg-severity-critical text-white',
    HIGH: 'bg-severity-high text-white',
    MEDIUM: 'bg-severity-medium text-black',
    LOW: 'bg-severity-low text-white',
    INFO: 'bg-severity-info text-white',
  };
  return m[s];
}

export default function IncidentList({ incidents }: Props) {
  const nav = useNavigate();

  return (
    <div className="bg-bg-card border border-border rounded">
      <div className="px-3 py-2 border-b border-border">
        <span className="text-xs font-medium text-text-secondary">Recent Incidents</span>
      </div>
      {incidents.length === 0 ? (
        <div className="p-4 text-center text-xs text-text-secondary">No incidents detected.</div>
      ) : (
        <div className="divide-y divide-border">
          {incidents.slice(0, 10).map((inc) => (
            <div
              key={inc.incident_id}
              className="px-3 py-2.5 flex items-center gap-3 hover:bg-bg-main cursor-pointer transition-colors"
              onClick={() => nav(`/incidents/${inc.incident_id}`)}
            >
              <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${badgeCls(inc.severity)}`}>
                {inc.severity}
              </span>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-medium text-text-primary">{inc.incident_type}</div>
                <div className="text-[10px] text-text-secondary truncate">
                  {inc.source_ips.join(', ')} → {inc.target_user || 'N/A'} · {inc.total_events} events
                </div>
              </div>
              <div className="text-right shrink-0">
                <div className="text-[10px] text-text-secondary">{formatTime(inc.first_seen)}</div>
                <div className="text-[10px] text-primary">{inc.confidence}%</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
