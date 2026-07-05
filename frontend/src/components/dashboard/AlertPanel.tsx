import type { Alert, Severity } from '../../types';
import { formatTime } from '../../utils/formatters';

interface Props {
  alerts: Alert[];
}

function severityColor(s: Severity): string {
  const map: Record<Severity, string> = {
    CRITICAL: 'border-severity-critical',
    HIGH: 'border-severity-high',
    MEDIUM: 'border-severity-medium',
    LOW: 'border-severity-low',
    INFO: 'border-severity-info',
  };
  return map[s];
}

export default function AlertPanel({ alerts }: Props) {
  const active = alerts.filter(a => a.status === 'ACTIVE').slice(0, 6);

  return (
    <div className="bg-bg-card border border-border rounded">
      <div className="px-3 py-2 border-b border-border flex items-center justify-between">
        <span className="text-xs font-medium text-text-secondary">Active Threats</span>
        <span className="text-[10px] text-text-secondary">{active.length} active</span>
      </div>
      {active.length === 0 ? (
        <div className="p-4 text-center text-xs text-text-secondary">No active threats detected.</div>
      ) : (
        <div className="grid grid-cols-3 gap-2 p-3">
          {active.map((alert) => (
            <div
              key={alert.alert_id}
              className={`border-l-3 ${severityColor(alert.severity)} bg-bg-main rounded px-3 py-2`}
            >
              <div className="text-xs font-medium text-text-primary">{alert.rule_name}</div>
              <div className="text-[10px] text-text-secondary mt-1">
                {alert.source_ip || 'N/A'} · {alert.event_count} events
              </div>
              <div className="text-[10px] text-text-secondary">
                {formatTime(alert.timestamp)}
                {alert.mitre && <span className="ml-1 text-primary">[{alert.mitre}]</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
