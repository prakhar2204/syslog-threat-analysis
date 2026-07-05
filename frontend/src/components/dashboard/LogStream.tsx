import { useRef, useEffect, useState } from 'react';
import type { LogEntry, Severity } from '../../types';
import { formatTime, truncate } from '../../utils/formatters';

interface Props {
  logs: LogEntry[];
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const cls: Record<Severity, string> = {
    CRITICAL: 'bg-severity-critical text-white',
    HIGH: 'bg-severity-high text-white',
    MEDIUM: 'bg-severity-medium text-black',
    LOW: 'bg-severity-low text-white',
    INFO: 'bg-severity-info text-white',
  };
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${cls[severity]}`}>
      {severity}
    </span>
  );
}

export default function LogStream({ logs }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = 0;
    }
  }, [logs, autoScroll]);

  const handleScroll = () => {
    if (!containerRef.current) return;
    setAutoScroll(containerRef.current.scrollTop < 10);
  };

  return (
    <div className="bg-bg-card border border-border rounded">
      <div className="px-3 py-2 border-b border-border flex items-center justify-between">
        <span className="text-xs font-medium text-text-secondary">Live Log Stream</span>
        <span className="text-[10px] text-text-secondary">{logs.length} entries</span>
      </div>
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="log-stream overflow-y-auto max-h-64 text-xs font-mono"
      >
        {logs.length === 0 ? (
          <div className="p-4 text-center text-text-secondary text-xs">
            No logs received. Start monitoring a log file.
          </div>
        ) : (
          <table className="w-full">
            <thead className="sticky top-0 bg-bg-card">
              <tr className="text-left text-[10px] text-text-secondary border-b border-border">
                <th className="px-2 py-1.5 w-16">Time</th>
                <th className="px-2 py-1.5 w-16">Severity</th>
                <th className="px-2 py-1.5 w-24">Source</th>
                <th className="px-2 py-1.5 w-20">Service</th>
                <th className="px-2 py-1.5">Message</th>
              </tr>
            </thead>
            <tbody>
              {logs.slice(0, 200).map((entry) => (
                <tr
                  key={entry.event_id}
                  className={`severity-row-${entry.severity} border-b border-border/50 hover:bg-bg-main transition-colors`}
                >
                  <td className="px-2 py-1 text-text-secondary">{formatTime(entry.timestamp)}</td>
                  <td className="px-2 py-1"><SeverityBadge severity={entry.severity} /></td>
                  <td className="px-2 py-1">{entry.source_ip || '—'}</td>
                  <td className="px-2 py-1">{entry.service || '—'}</td>
                  <td className="px-2 py-1 text-text-primary">{truncate(entry.message, 120)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
