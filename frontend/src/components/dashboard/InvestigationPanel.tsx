/* SysLog Threat Analysis - Investigation Panel
 *
 * Replaces AlertPanel. Displays recent investigations showing
 * Evidence objects and Observations instead of raw alerts.
 */

import { useEffect, useState } from 'react';
import { api } from '../../services/api';
import { formatTime } from '../../utils/formatters';
import type { Evidence, Observation, Severity } from '../../types';
import { Search, Eye, CheckCircle, XCircle } from 'lucide-react';

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

type InvestigationItem = {
  id: string;
  type: 'evidence' | 'observation';
  rule_name: string;
  severity: Severity;
  source_ip: string;
  username: string;
  event_count: number;
  conditions_met: number;
  conditions_total: number;
  time_window: string;
  confidence: number;
};

function toItem(ev: Evidence): InvestigationItem {
  return {
    id: ev.evidence_id,
    type: 'evidence',
    rule_name: ev.rule_name,
    severity: ev.severity,
    source_ip: ev.source_ips[0] || '-',
    username: ev.usernames[0] || '-',
    event_count: ev.event_count,
    conditions_met: ev.matched_conditions.filter(c => c.matched).length,
    conditions_total: ev.matched_conditions.length,
    time_window: `${formatTime(ev.first_seen)} - ${formatTime(ev.last_seen)}`,
    confidence: ev.collection_confidence,
  };
}

function obsToItem(obs: Observation): InvestigationItem {
  return {
    id: obs.observation_id,
    type: 'observation',
    rule_name: obs.rule_name,
    severity: obs.severity,
    source_ip: obs.source_ips[0] || '-',
    username: obs.usernames[0] || '-',
    event_count: obs.event_count,
    conditions_met: obs.matched_conditions.filter(c => c.matched).length,
    conditions_total: obs.matched_conditions.length,
    time_window: `${formatTime(obs.first_seen)} - ${formatTime(obs.last_seen)}`,
    confidence: obs.collection_confidence,
  };
}

export default function InvestigationPanel() {
  const [items, setItems] = useState<InvestigationItem[]>([]);

  useEffect(() => {
    const load = async () => {
      try {
        const [evidence, observations] = await Promise.all([
          api.getEvidence(),
          api.getObservations(),
        ]);
        const all = [
          ...evidence.map(toItem),
          ...observations.filter(o => o.status === 'OPEN').map(obsToItem),
        ].sort((a, b) => b.event_count - a.event_count).slice(0, 8);
        setItems(all);
      } catch { /* ignore */ }
    };
    load();
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  }, []);

  return (
    <div className="bg-bg-card border border-border rounded">
      <div className="px-3 py-2 border-b border-border flex items-center justify-between">
        <span className="text-xs font-medium text-text-secondary flex items-center gap-1.5">
          <Search size={12} /> Recent Investigations
        </span>
        <span className="text-[10px] text-text-secondary">{items.length} active</span>
      </div>
      {items.length === 0 ? (
        <div className="p-4 text-center text-xs text-text-secondary">No investigations yet.</div>
      ) : (
        <div className="grid grid-cols-2 gap-2 p-3">
          {items.map((item) => (
            <div
              key={item.id}
              className={`border-l-3 ${severityColor(item.severity)} bg-bg-main rounded px-3 py-2`}
            >
              <div className="flex items-center justify-between">
                <div className="text-xs font-medium text-text-primary">{item.rule_name}</div>
                <span className={`text-[9px] px-1 py-0.5 rounded ${
                  item.type === 'evidence' ? 'bg-primary/10 text-primary' : 'bg-severity-medium/10 text-severity-medium'
                }`}>
                  {item.type === 'evidence' ? 'Incident' : 'Observation'}
                </span>
              </div>
              <div className="mt-1 space-y-0.5 text-[10px] text-text-secondary">
                <div className="flex items-center gap-2">
                  <span>{item.event_count} events</span>
                  <span>·</span>
                  <span className="font-mono">{item.source_ip}</span>
                  {item.username !== '-' && <><span>·</span><span>{item.username}</span></>}
                </div>
                <div className="flex items-center gap-1">
                  {item.conditions_total > 0 && (
                    <span className="flex items-center gap-0.5">
                      {item.conditions_met === item.conditions_total ? (
                        <CheckCircle size={9} className="text-severity-info" />
                      ) : (
                        <Eye size={9} className="text-severity-medium" />
                      )}
                      {item.conditions_met}/{item.conditions_total} conditions
                    </span>
                  )}
                </div>
                <div className="text-text-secondary/70">{item.time_window}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
