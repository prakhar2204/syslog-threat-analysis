import { Fragment, useEffect, useState, useCallback } from 'react';
import { api } from '../services/api';
import type { LogEntry, LogDetail, Severity } from '../types';
import { formatTime, truncate } from '../utils/formatters';
import { Search, ChevronDown, ChevronRight } from 'lucide-react';

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const EVENT_TYPES = ['Authentication', 'Network', 'Firewall', 'Web Server', 'System', 'Kernel', 'Application', 'Unknown'];

export default function Logs() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [eventType, setEventType] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detail, setDetail] = useState<LogDetail | null>(null);
  const limit = 50;

  const fetchLogs = useCallback(async () => {
    try {
      const res = await api.getLogs({
        search, severity, event_type: eventType, source_ip: sourceIp,
        limit, offset: page * limit,
      });
      setEntries(res.items);
      setTotal(res.total);
    } catch { /* silent */ }
  }, [search, severity, eventType, sourceIp, page]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const toggleExpand = async (id: string) => {
    if (expanded === id) {
      setExpanded(null);
      setDetail(null);
      return;
    }
    setExpanded(id);
    try {
      const d = await api.getLogDetail(id);
      setDetail(d);
    } catch { setDetail(null); }
  };

  const totalPages = Math.ceil(total / limit);

  const badgeCls = (s: Severity): string => {
    const m: Record<Severity, string> = {
      CRITICAL: 'bg-severity-critical text-white',
      HIGH: 'bg-severity-high text-white',
      MEDIUM: 'bg-severity-medium text-black',
      LOW: 'bg-severity-low text-white',
      INFO: 'bg-severity-info text-white',
    };
    return m[s];
  };

  return (
    <div className="space-y-3">
      <div className="text-sm font-semibold text-text-primary">Log Explorer</div>

      {/* Filters */}
      <div className="bg-bg-card border border-border rounded p-3 flex flex-wrap gap-2 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-text-secondary" />
          <input
            type="text"
            placeholder="Search logs (IP, keyword, username, rule ID, MITRE)…"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0); }}
            className="w-full text-xs border border-border rounded pl-7 pr-2 py-1.5 bg-bg-card"
          />
        </div>
        <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(0); }} className="text-xs border border-border rounded px-2 py-1.5 bg-bg-card">
          <option value="">All Severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={eventType} onChange={e => { setEventType(e.target.value); setPage(0); }} className="text-xs border border-border rounded px-2 py-1.5 bg-bg-card">
          <option value="">All Event Types</option>
          {EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <input
          type="text"
          placeholder="Source IP"
          value={sourceIp}
          onChange={e => { setSourceIp(e.target.value); setPage(0); }}
          className="text-xs border border-border rounded px-2 py-1.5 bg-bg-card w-32"
        />
        <span className="text-[10px] text-text-secondary">{total.toLocaleString()} results</span>
      </div>

      {/* Table */}
      <div className="bg-bg-card border border-border rounded overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-bg-main">
            <tr className="text-left text-[10px] text-text-secondary border-b border-border">
              <th className="px-2 py-2 w-6"></th>
              <th className="px-2 py-2 w-16">Time</th>
              <th className="px-2 py-2 w-16">Severity</th>
              <th className="px-2 py-2 w-20">Type</th>
              <th className="px-2 py-2 w-24">Source IP</th>
              <th className="px-2 py-2 w-16">Service</th>
              <th className="px-2 py-2">Message</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(entry => (
              <Fragment key={entry.event_id}>
                <tr
                  className={`severity-row-${entry.severity} border-b border-border/50 hover:bg-bg-main cursor-pointer transition-colors`}
                  onClick={() => toggleExpand(entry.event_id)}
                >
                  <td className="px-2 py-1.5 text-text-secondary">
                    {expanded === entry.event_id ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                  </td>
                  <td className="px-2 py-1.5 text-text-secondary font-mono">{formatTime(entry.timestamp)}</td>
                  <td className="px-2 py-1.5"><span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${badgeCls(entry.severity)}`}>{entry.severity}</span></td>
                  <td className="px-2 py-1.5 text-text-secondary">{entry.event_type}</td>
                  <td className="px-2 py-1.5 font-mono">{entry.source_ip || '—'}</td>
                  <td className="px-2 py-1.5">{entry.service || '—'}</td>
                  <td className="px-2 py-1.5">{truncate(entry.message, 100)}</td>
                </tr>
                {expanded === entry.event_id && detail && (
                  <tr key={`${entry.event_id}-detail`}>
                    <td colSpan={7} className="bg-bg-main p-3 border-b border-border">
                      <div className="space-y-2 text-xs">
                        <div>
                          <span className="font-medium text-text-secondary">Raw Log:</span>
                          <pre className="mt-1 bg-bg-card border border-border rounded p-2 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">{detail.entry.raw_log}</pre>
                        </div>
                        <div className="grid grid-cols-4 gap-2">
                          <div><span className="text-text-secondary">Hostname:</span> {detail.entry.hostname || '—'}</div>
                          <div><span className="text-text-secondary">Username:</span> {detail.entry.username || '—'}</div>
                          <div><span className="text-text-secondary">Process:</span> {detail.entry.process || '—'}</div>
                          <div><span className="text-text-secondary">Format:</span> {detail.entry.log_format}</div>
                        </div>
                        {detail.triggered_rules.length > 0 && (
                          <div>
                            <span className="font-medium text-text-secondary">Detection Rules Triggered:</span>
                            <div className="mt-1 space-y-1">
                              {detail.triggered_rules.map(rule => (
                                <div key={rule.rule_id} className="bg-bg-card border border-border rounded p-2">
                                  <div className="font-medium">[{rule.rule_id}] {rule.name} <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${badgeCls(rule.severity)}`}>{rule.severity}</span></div>
                                  <div className="text-text-secondary mt-0.5">{rule.description}</div>
                                  {rule.mitre && <div className="text-primary mt-0.5">MITRE ATT&CK: {rule.mitre}</div>}
                                  <div className="text-text-secondary mt-0.5">{rule.recommendation}</div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-xs text-text-secondary">
          <span>Page {page + 1} of {totalPages}</span>
          <div className="flex gap-1">
            <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="px-2 py-1 border border-border rounded disabled:opacity-30">Prev</button>
            <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="px-2 py-1 border border-border rounded disabled:opacity-30">Next</button>
          </div>
        </div>
      )}
    </div>
  );
}
