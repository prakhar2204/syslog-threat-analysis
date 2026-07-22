/* SysLog Threat Analysis — IOC Intelligence Panel (Phase 5.5: Pivot Navigation) */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Fingerprint, ChevronDown, ChevronRight, ArrowRight, X } from 'lucide-react';
import type { Evidence, Incident, IOCRelationship } from '../../types';
import { api } from '../../services/api';

interface Props {
  evidence: Evidence;
  incident: Incident;
}

interface IOCRow {
  type: string;
  value: string;
  occurrences: number;
  relatedRules: string[];
  mitre: string[];
}

/* --- IOC Detail Drawer --- */
function IOCDetailDrawer({ ioc, relatedIOCs, onClose }: {
  ioc: IOCRelationship;
  relatedIOCs: IOCRelationship[];
  onClose: () => void;
}) {
  const nav = useNavigate();
  return (
    <div className="fixed inset-y-0 right-0 w-80 bg-bg-card border-l border-border shadow-2xl z-40 flex flex-col">
      {/* Drawer header */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border shrink-0">
        <Fingerprint size={14} className="text-primary" />
        <div className="flex-1 min-w-0">
          <div className="text-[10px] text-text-secondary uppercase">{ioc.ioc_type}</div>
          <div className="text-xs font-mono font-semibold text-text-primary truncate">{ioc.value}</div>
        </div>
        <button onClick={onClose} className="p-1 rounded hover:bg-bg-main transition">
          <X size={14} className="text-text-secondary" />
        </button>
      </div>

      <div className="overflow-y-auto flex-1 p-4 space-y-4 text-xs">
        {/* Stats */}
        <div className="grid grid-cols-3 gap-2">
          {[
            { label: 'Occurrences', value: ioc.occurrences },
            { label: 'Alerts', value: ioc.related_alerts },
            { label: 'Incidents', value: ioc.related_incidents },
          ].map(({ label, value }) => (
            <div key={label} className="bg-bg-main rounded p-2 border border-border text-center">
              <div className="text-[9px] text-text-secondary uppercase">{label}</div>
              <div className="font-bold text-text-primary">{value}</div>
            </div>
          ))}
        </div>

        {/* Confidence */}
        <div>
          <div className="text-[10px] text-text-secondary uppercase mb-1">Confidence</div>
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 bg-bg-main rounded-full overflow-hidden">
              <div className="h-full bg-primary rounded-full" style={{ width: `${ioc.confidence}%` }} />
            </div>
            <span className="text-[10px] font-mono text-primary">{ioc.confidence.toFixed(0)}%</span>
          </div>
        </div>

        {/* Related Users */}
        {ioc.related_users.length > 0 && (
          <div>
            <div className="text-[10px] text-text-secondary uppercase mb-1">Related Users</div>
            <div className="flex flex-wrap gap-1">
              {ioc.related_users.map(u => (
                <span key={u} className="text-[10px] px-1.5 py-0.5 rounded bg-bg-main border border-border font-mono">{u}</span>
              ))}
            </div>
          </div>
        )}

        {/* Related Hosts */}
        {ioc.related_hosts.length > 0 && (
          <div>
            <div className="text-[10px] text-text-secondary uppercase mb-1">Related Hosts</div>
            <div className="flex flex-wrap gap-1">
              {ioc.related_hosts.map(h => (
                <span key={h} className="text-[10px] px-1.5 py-0.5 rounded bg-bg-main border border-border font-mono">{h}</span>
              ))}
            </div>
          </div>
        )}

        {/* Related Services */}
        {ioc.related_services.length > 0 && (
          <div>
            <div className="text-[10px] text-text-secondary uppercase mb-1">Related Services</div>
            <div className="flex flex-wrap gap-1">
              {ioc.related_services.map(s => (
                <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">{s}</span>
              ))}
            </div>
          </div>
        )}

        {/* Related Rules */}
        {ioc.related_rules.length > 0 && (
          <div>
            <div className="text-[10px] text-text-secondary uppercase mb-1">Triggered Rules</div>
            <div className="flex flex-wrap gap-1">
              {ioc.related_rules.map(r => (
                <span key={r} className="text-[10px] px-1.5 py-0.5 rounded bg-bg-main border border-border font-mono">{r}</span>
              ))}
            </div>
          </div>
        )}

        {/* Related IOCs (pivot) */}
        {relatedIOCs.length > 0 && (
          <div>
            <div className="text-[10px] text-text-secondary uppercase mb-1">Related IOCs</div>
            <div className="space-y-1">
              {relatedIOCs.slice(0, 8).map((r, i) => (
                <div key={i} className="flex items-center gap-2 text-[10px] p-1.5 rounded bg-bg-main border border-border">
                  <span className="text-[9px] px-1 py-0.5 rounded bg-primary/10 text-primary">{r.ioc_type}</span>
                  <span className="font-mono text-text-primary flex-1 truncate">{r.value}</span>
                  <span className="text-text-secondary">{r.occurrences}×</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Pivot: navigate to related incidents */}
        {ioc.related_incidents > 0 && (
          <div>
            <div className="text-[10px] text-text-secondary uppercase mb-1">Incidents ({ioc.related_incidents})</div>
            <button
              onClick={() => { onClose(); nav('/incidents'); }}
              className="flex items-center gap-1 text-[10px] text-primary hover:underline"
            >
              View all incidents <ArrowRight size={10} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function IOCPanel({ evidence, incident }: Props) {
  const [selected, setSelected] = useState<{ ioc: IOCRelationship; related: IOCRelationship[] } | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  if (evidence.extracted_iocs.length === 0) return null;

  // Aggregate IOCs by value
  const iocMap = new Map<string, IOCRow>();
  for (const ioc of evidence.extracted_iocs) {
    const key = `${ioc.ioc_type}:${ioc.value}`;
    if (iocMap.has(key)) {
      iocMap.get(key)!.occurrences++;
    } else {
      iocMap.set(key, {
        type: ioc.ioc_type,
        value: ioc.value,
        occurrences: 1,
        relatedRules: [...incident.triggered_rules],
        mitre: [...incident.mitre_techniques],
      });
    }
  }

  const rows = Array.from(iocMap.values()).sort((a, b) => b.occurrences - a.occurrences);
  const visible = showAll ? rows : rows.slice(0, 25);

  const handleRowClick = async (row: IOCRow) => {
    const key = `${row.type}:${row.value}`;
    if (loading === key) return;
    setLoading(key);
    try {
      const data = await api.getIOCDetail(row.type, row.value);
      setSelected({ ioc: data.ioc, related: data.related });
    } catch {
      // IOC not yet in relationship engine — show minimal info
      const fallback: IOCRelationship = {
        ioc_type: row.type, value: row.value,
        first_seen: null, last_seen: null,
        occurrences: row.occurrences,
        related_alerts: 0, related_incidents: 0,
        related_users: [], related_services: [],
        related_hosts: [], related_rules: row.relatedRules,
        related_ips: [], confidence: 0,
      };
      setSelected({ ioc: fallback, related: [] });
    } finally {
      setLoading(null);
    }
  };

  return (
    <>
      <div className="bg-bg-card border border-border rounded p-4">
        <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
          <Fingerprint size={14} className="text-primary" />
          IOC Intelligence
          <span className="text-[10px] text-text-secondary font-normal ml-auto">
            {rows.length} unique IOCs · <span className="text-primary">click a row to pivot</span>
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="text-[9px] text-text-secondary uppercase tracking-wider border-b border-border">
                <th className="text-left py-1.5 pr-3">Type</th>
                <th className="text-left py-1.5 pr-3">Value</th>
                <th className="text-center py-1.5 pr-3">Occ.</th>
                <th className="text-left py-1.5 pr-3">Related Rules</th>
                <th className="text-left py-1.5">MITRE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {visible.map((row, i) => {
                const key = `${row.type}:${row.value}`;
                const isLoading = loading === key;
                return (
                  <tr
                    key={i}
                    onClick={() => handleRowClick(row)}
                    className="hover:bg-bg-main transition-colors cursor-pointer group"
                    title="Click to view IOC relationships"
                  >
                    <td className="py-1.5 pr-3">
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-primary/10 text-primary font-medium">
                        {row.type}
                      </span>
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-text-primary">
                      <span className="group-hover:text-primary transition-colors">{row.value}</span>
                      {isLoading && <span className="ml-1 text-[9px] text-text-secondary animate-pulse">loading…</span>}
                    </td>
                    <td className="py-1.5 pr-3 text-center font-semibold">{row.occurrences}</td>
                    <td className="py-1.5 pr-3">
                      <div className="flex flex-wrap gap-0.5">
                        {row.relatedRules.slice(0, 2).map(r => (
                          <span key={r} className="text-[9px] px-1 py-0.5 rounded bg-bg-main text-text-secondary">{r}</span>
                        ))}
                      </div>
                    </td>
                    <td className="py-1.5">
                      {row.mitre.slice(0, 2).map(t => (
                        <span key={t} className="text-[9px] px-1 py-0.5 rounded bg-primary/10 text-primary font-mono mr-0.5">{t}</span>
                      ))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {rows.length > 25 && (
            <button
              onClick={() => setShowAll(v => !v)}
              className="w-full text-[10px] text-primary hover:underline text-center pt-2 flex items-center justify-center gap-1"
            >
              {showAll ? <><ChevronDown size={10} /> Show less</> : <><ChevronRight size={10} /> +{rows.length - 25} more IOCs</>}
            </button>
          )}
        </div>
      </div>

      {/* Pivot drawer */}
      {selected && (
        <>
          <div className="fixed inset-0 z-30 bg-black/20" onClick={() => setSelected(null)} />
          <IOCDetailDrawer
            ioc={selected.ioc}
            relatedIOCs={selected.related}
            onClose={() => setSelected(null)}
          />
        </>
      )}
    </>
  );
}
