import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import type { Incident, Severity, Evidence, RawLogRef } from '../types';
import { formatTime, formatDateTime, relativeTime, formatDuration } from '../utils/formatters';
import DetectionExplanation from '../components/investigation/DetectionExplanation';
import IOCPanel from '../components/investigation/IOCPanel';
import {
  ArrowLeft, ArrowRight, Clock, Shield, AlertTriangle, CheckCircle, XCircle,
  Search, FileText, ChevronDown, ChevronRight, Target, User, Server, Hash,
  Fingerprint, Activity,
} from 'lucide-react';

function SevBadge({ s }: { s: Severity }) {
  const cls: Record<Severity, string> = {
    CRITICAL: 'bg-severity-critical text-white',
    HIGH: 'bg-severity-high text-white',
    MEDIUM: 'bg-severity-medium text-black',
    LOW: 'bg-severity-low text-white',
    INFO: 'bg-severity-info text-white',
  };
  return <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${cls[s]}`}>{s}</span>;
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

/* ---------- Incident List Page ---------- */
export default function Incidents() {
  const { state } = useApp();
  const nav = useNavigate();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    api.getIncidents().then(setIncidents).catch(() => {});
  }, [state.incidents.length]);

  const toggle = (id: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-sm font-semibold text-text-primary">Incidents</div>
      {incidents.length === 0 ? (
        <div className="bg-bg-card border border-border rounded p-6 text-center text-xs text-text-secondary">No incidents detected yet.</div>
      ) : (
        <div className="space-y-2">
          {incidents.map(inc => {
            const isExpanded = expanded.has(inc.incident_id);
            return (
              <div
                key={inc.incident_id}
                className={`bg-bg-card border-l-4 ${sevBorder(inc.severity)} border border-border rounded overflow-hidden transition-shadow hover:shadow-sm`}
              >
                {/* Card header — always visible */}
                <div className="p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <SevBadge s={inc.severity} />
                    <span className="text-xs font-semibold text-text-primary flex-1 truncate">{inc.incident_type}</span>
                    <span className="text-[10px] text-primary font-semibold">{inc.confidence}%</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded border border-border text-text-secondary">{inc.risk}</span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-bg-main text-text-secondary">{inc.status}</span>
                  </div>

                  {/* Key details grid */}
                  <div className="grid grid-cols-4 gap-x-4 gap-y-1 text-[10px] text-text-secondary mb-2">
                    <div className="flex items-center gap-1"><Target size={9} /> <span className="font-mono text-text-primary">{inc.source_ips[0] || '—'}</span></div>
                    <div className="flex items-center gap-1"><User size={9} /> {inc.target_user || '—'}</div>
                    <div className="flex items-center gap-1"><Hash size={9} /> {inc.total_events} events</div>
                    <div className="flex items-center gap-1"><Activity size={9} /> {inc.related_alert_ids.length} alerts</div>
                    <div className="flex items-center gap-1"><Clock size={9} /> {formatTime(inc.first_seen)}</div>
                    <div className="flex items-center gap-1"><Clock size={9} /> {formatTime(inc.last_seen)}</div>
                    <div className="flex items-center gap-1"><Server size={9} /> {inc.triggered_rules[0] || '—'}</div>
                    <div>Duration: {formatDuration(inc.first_seen, inc.last_seen)}</div>
                  </div>

                  {/* MITRE tags */}
                  {inc.mitre_techniques.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-2">
                      {inc.mitre_techniques.map(t => (
                        <span key={t} className="text-[9px] px-1.5 py-0.5 rounded bg-primary/10 text-primary font-mono">{t}</span>
                      ))}
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => nav(`/incidents/${inc.incident_id}`)}
                      className="flex items-center gap-1 text-[10px] text-primary hover:underline font-medium"
                    >
                      Investigate <ArrowRight size={10} />
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); toggle(inc.incident_id); }}
                      className="flex items-center gap-1 text-[10px] text-text-secondary hover:text-text-primary transition"
                    >
                      {isExpanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
                      {isExpanded ? 'Collapse' : 'Expand'}
                    </button>
                  </div>
                </div>

                {/* Expanded section */}
                {isExpanded && (
                  <div className="border-t border-border p-3 bg-bg-main space-y-2">
                    <div className="text-xs text-text-primary">{inc.description}</div>
                    {inc.reasoning && (
                      <div className="text-xs text-text-secondary italic">{inc.reasoning}</div>
                    )}
                    {inc.timeline.length > 0 && (
                      <div>
                        <div className="text-[9px] font-semibold uppercase text-text-secondary mb-1">Timeline Preview</div>
                        <div className="flex flex-wrap gap-1">
                          {inc.timeline.slice(0, 5).map((e, i) => (
                            <span key={i} className="text-[9px] px-1.5 py-0.5 rounded bg-bg-card border border-border">
                              {formatTime(e.timestamp)} — {e.description}
                            </span>
                          ))}
                          {inc.timeline.length > 5 && (
                            <span className="text-[9px] text-text-secondary">+{inc.timeline.length - 5} more</span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ---------- Raw Log Viewer ---------- */
function RawLogViewer({ logRef }: { logRef: RawLogRef }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-border rounded text-[11px]">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-2 py-1.5 hover:bg-bg-main transition text-left"
      >
        {expanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
        <span className="text-text-secondary font-mono">{formatTime(logRef.timestamp)}</span>
        <SevBadge s={logRef.severity as Severity} />
        <span className="text-text-primary truncate flex-1">{logRef.message}</span>
        {logRef.detection_rule_ids.length > 0 && (
          <span className="text-[9px] text-primary">{logRef.detection_rule_ids.join(', ')}</span>
        )}
      </button>
      {expanded && (
        <div className="border-t border-border p-2 space-y-2 bg-bg-main">
          <div>
            <div className="text-[9px] text-text-secondary uppercase mb-0.5">Original Log</div>
            <pre className="text-[10px] font-mono text-text-primary whitespace-pre-wrap bg-bg-card p-2 rounded border border-border">{logRef.raw_log}</pre>
          </div>
          <div className="grid grid-cols-3 gap-2 text-[10px]">
            <div><span className="text-text-secondary">Hostname:</span> <span className="font-mono">{logRef.hostname}</span></div>
            <div><span className="text-text-secondary">Source IP:</span> <span className="font-mono">{logRef.source_ip || '-'}</span></div>
            <div><span className="text-text-secondary">Dest IP:</span> <span className="font-mono">{logRef.destination_ip || '-'}</span></div>
            <div><span className="text-text-secondary">Username:</span> <span className="font-mono">{logRef.username || '-'}</span></div>
            <div><span className="text-text-secondary">Service:</span> <span className="font-mono">{logRef.service}</span></div>
            <div><span className="text-text-secondary">Process:</span> <span className="font-mono">{logRef.process}</span></div>
            <div><span className="text-text-secondary">Event Type:</span> <span>{logRef.event_type}</span></div>
            <div><span className="text-text-secondary">Severity:</span> <SevBadge s={logRef.severity as Severity} /></div>
            <div><span className="text-text-secondary">Rules:</span> <span className="text-primary font-mono">{logRef.detection_rule_ids.join(', ') || '-'}</span></div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------- Enhanced Timeline ---------- */
function AttackTimeline({ incident }: { incident: Incident }) {
  if (incident.timeline.length === 0) return null;

  const timelineEvents = incident.timeline;
  const sevNode = (s: Severity | string): string => {
    switch (s) {
      case 'CRITICAL': return '#dc3545';
      case 'HIGH': return '#e67700';
      case 'MEDIUM': return '#ffc107';
      case 'LOW': return '#0d6efd';
      default: return '#1a73e8';
    }
  };

  return (
    <div className="bg-bg-card border border-border rounded p-4">
      <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
        <Clock size={14} className="text-primary" /> Attack Timeline
        <span className="text-[10px] text-text-secondary font-normal ml-auto">{timelineEvents.length} events</span>
      </div>
      <div className="relative pl-4 border-l-2 border-border space-y-3">
        {timelineEvents.map((evt, i) => {
          const prevTs = i > 0 ? timelineEvents[i - 1].timestamp : null;
          const gap = prevTs ? formatDuration(prevTs, evt.timestamp) : null;
          return (
            <div key={i} className="relative">
              <div
                className="absolute -left-[21px] w-2.5 h-2.5 rounded-full border-2 border-bg-card"
                style={{ backgroundColor: sevNode(evt.severity) }}
              />
              {gap && i > 0 && (
                <div className="absolute -left-[14px] -top-3 text-[8px] text-text-secondary font-mono bg-bg-card px-0.5">
                  +{gap}
                </div>
              )}
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-text-secondary font-mono w-16 shrink-0">{formatTime(evt.timestamp)}</span>
                <SevBadge s={evt.severity} />
                <span className="text-xs text-text-primary">{evt.description}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- Grouped Evidence Section ---------- */
function EvidenceSection({ evidence }: { evidence: Evidence }) {
  const [openSections, setOpenSections] = useState<Set<string>>(new Set(['conditions', 'iocs']));

  const toggleSection = (key: string) => {
    setOpenSections(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  const Section = ({ id, title, icon, count, children }: { id: string; title: string; icon: React.ReactNode; count: number; children: React.ReactNode }) => {
    const open = openSections.has(id);
    return (
      <div className="border border-border rounded">
        <button
          onClick={() => toggleSection(id)}
          className="w-full flex items-center gap-2 px-3 py-2 hover:bg-bg-main transition text-left"
        >
          {open ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
          {icon}
          <span className="text-[10px] font-semibold text-text-primary flex-1">{title}</span>
          <span className="text-[9px] text-text-secondary">{count}</span>
        </button>
        {open && <div className="border-t border-border p-3">{children}</div>}
      </div>
    );
  };

  return (
    <div className="bg-bg-card border border-border rounded p-4">
      <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
        <Search size={14} className="text-primary" />
        Evidence
        <span className="text-[10px] text-text-secondary font-normal ml-auto">
          {evidence.evidence_id} · {evidence.collection_confidence.toFixed(0)}% confidence
        </span>
      </div>

      {/* Evidence summary */}
      <div className="grid grid-cols-4 gap-3 mb-3 text-xs">
        <div><span className="text-text-secondary">Rule:</span><br /><span className="font-medium">{evidence.rule_name}</span></div>
        <div><span className="text-text-secondary">Source:</span><br /><span className="font-mono">{evidence.source_ips[0] || '-'}</span></div>
        <div><span className="text-text-secondary">Events:</span><br />{evidence.event_count}</div>
        <div><span className="text-text-secondary">Alerts:</span><br />{evidence.related_alert_ids.length}</div>
      </div>

      {/* Expandable sections */}
      <div className="space-y-1.5">
        {evidence.matched_conditions.length > 0 && (
          <Section id="conditions" title="Matched Conditions" icon={<CheckCircle size={10} className="text-severity-info" />} count={evidence.matched_conditions.length}>
            <div className="space-y-1">
              {evidence.matched_conditions.map((cond, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  {cond.matched ? <CheckCircle size={11} className="text-severity-info shrink-0" /> : <XCircle size={11} className="text-severity-critical shrink-0" />}
                  <span className="text-text-primary">{cond.condition}</span>
                  {cond.value && <span className="text-text-secondary font-mono text-[10px]">{cond.value}</span>}
                </div>
              ))}
            </div>
          </Section>
        )}

        {evidence.extracted_iocs.length > 0 && (
          <Section id="iocs" title="Extracted IOCs" icon={<Fingerprint size={10} className="text-severity-critical" />} count={evidence.extracted_iocs.length}>
            <div className="flex flex-wrap gap-1">
              {evidence.extracted_iocs.slice(0, 20).map((ioc, i) => (
                <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-bg-main border border-border font-mono">
                  <span className="text-text-secondary">{ioc.ioc_type}:</span> {ioc.value}
                </span>
              ))}
              {evidence.extracted_iocs.length > 20 && (
                <span className="text-[10px] text-text-secondary">+{evidence.extracted_iocs.length - 20} more</span>
              )}
            </div>
          </Section>
        )}

        {evidence.raw_log_refs.length > 0 && (
          <Section id="raw" title="Raw Logs" icon={<FileText size={10} className="text-text-secondary" />} count={evidence.raw_log_refs.length}>
            <div className="space-y-1 max-h-64 overflow-y-auto">
              {evidence.raw_log_refs.map(ref => (
                <RawLogViewer key={ref.event_id} logRef={ref} />
              ))}
            </div>
          </Section>
        )}

        {/* Confidence contribution */}
        <Section id="confidence" title="Confidence Contribution" icon={<Shield size={10} className="text-primary" />} count={0}>
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div className="bg-bg-main rounded p-2 border border-border">
              <div className="text-[9px] text-text-secondary">Collection</div>
              <div className="font-semibold text-primary">{evidence.collection_confidence.toFixed(0)}%</div>
            </div>
            <div className="bg-bg-main rounded p-2 border border-border">
              <div className="text-[9px] text-text-secondary">Unique Sources</div>
              <div className="font-semibold">{evidence.unique_source_count}</div>
            </div>
            <div className="bg-bg-main rounded p-2 border border-border">
              <div className="text-[9px] text-text-secondary">Unique Destinations</div>
              <div className="font-semibold">{evidence.unique_dest_count}</div>
            </div>
          </div>
        </Section>
      </div>
    </div>
  );
}

/* ---------- Incident Detail Page ---------- */
export function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const nav = useNavigate();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);

  useEffect(() => {
    if (id) {
      api.getIncidentDetail(id).then(setIncident).catch(() => {});
      api.getEvidenceByIncident(id).then(setEvidence).catch(() => {});
    }
  }, [id]);

  if (!incident) return <div className="text-xs text-text-secondary p-4">Loading…</div>;

  return (
    <div className="space-y-3">
      <button onClick={() => nav('/incidents')} className="flex items-center gap-1 text-xs text-primary hover:underline">
        <ArrowLeft size={14} /> Back to Incidents
      </button>

      {/* Header */}
      <div className={`bg-bg-card border-l-4 ${sevBorder(incident.severity)} border border-border rounded p-4`}>
        <div className="flex items-center gap-3 mb-3">
          <SevBadge s={incident.severity} />
          <span className="text-sm font-semibold text-text-primary">{incident.incident_type}</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded border border-border text-text-secondary">{incident.status}</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded border border-border text-text-secondary">{incident.risk}</span>
          <span className="text-xs text-primary font-semibold ml-auto">{incident.confidence}% confidence</span>
        </div>
        <div className="grid grid-cols-4 gap-3 text-xs">
          <div><span className="text-text-secondary">Incident ID:</span><br /><span className="font-mono text-[10px]">{incident.incident_id}</span></div>
          <div><span className="text-text-secondary">Confidence:</span><br /><span className="text-primary font-semibold">{incident.confidence}%</span></div>
          <div><span className="text-text-secondary">Risk Level:</span><br />{incident.risk}</div>
          <div><span className="text-text-secondary">Total Events:</span><br />{incident.total_events}</div>
          <div><span className="text-text-secondary">Source IPs:</span><br /><span className="font-mono">{incident.source_ips.join(', ') || '—'}</span></div>
          <div><span className="text-text-secondary">Target User:</span><br />{incident.target_user || '—'}</div>
          <div><span className="text-text-secondary">First Seen:</span><br />{formatDateTime(incident.first_seen)}</div>
          <div><span className="text-text-secondary">Last Seen:</span><br />{formatDateTime(incident.last_seen)}</div>
        </div>
        {/* Duration bar */}
        <div className="mt-2 pt-2 border-t border-border text-[10px] text-text-secondary flex items-center gap-3">
          <span>Duration: <strong className="text-text-primary">{formatDuration(incident.first_seen, incident.last_seen)}</strong></span>
          <span>·</span>
          <span>{relativeTime(incident.last_seen)}</span>
          {incident.mitre_techniques.length > 0 && (
            <>
              <span>·</span>
              {incident.mitre_techniques.map(t => (
                <span key={t} className="px-1.5 py-0.5 rounded bg-primary/10 text-primary font-mono">{t}</span>
              ))}
            </>
          )}
        </div>
      </div>

      {/* Detection Explanation */}
      <DetectionExplanation incident={incident} evidence={evidence} />

      {/* Attack Timeline */}
      <AttackTimeline incident={incident} />

      {/* Evidence */}
      {evidence && <EvidenceSection evidence={evidence} />}

      {/* IOC Intelligence */}
      {evidence && <IOCPanel evidence={evidence} incident={incident} />}

      {/* Recommendations */}
      {incident.recommendations.length > 0 && (
        <div className="bg-bg-card border border-border rounded p-4">
          <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-2">
            <CheckCircle size={14} className="text-severity-info" /> Recommended Actions
          </div>
          <ul className="space-y-1">
            {incident.recommendations.map((rec, i) => (
              <li key={i} className="text-xs text-text-primary flex items-start gap-2">
                <span className="text-text-secondary">•</span> {rec}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Triggered Rules & MITRE */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-bg-card border border-border rounded p-4">
          <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-severity-high" /> Triggered Rules
          </div>
          {incident.triggered_rules.length > 0 ? (
            <div className="space-y-1">
              {incident.triggered_rules.map(r => (
                <div key={r} className="text-xs font-mono text-text-primary">{r}</div>
              ))}
            </div>
          ) : <div className="text-xs text-text-secondary">None</div>}
        </div>
        <div className="bg-bg-card border border-border rounded p-4">
          <div className="text-xs font-semibold text-text-primary mb-2">MITRE ATT&CK Techniques</div>
          {incident.mitre_techniques.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {incident.mitre_techniques.map(t => (
                <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-primary/10 text-primary font-mono">{t}</span>
              ))}
            </div>
          ) : <div className="text-xs text-text-secondary">None mapped</div>}
        </div>
      </div>

      {/* Related Logs */}
      {incident.related_logs && incident.related_logs.length > 0 && (
        <div className="bg-bg-card border border-border rounded p-4">
          <div className="text-xs font-semibold text-text-primary mb-2">Related Log Entries ({incident.related_logs.length})</div>
          <div className="max-h-48 overflow-y-auto text-[11px] font-mono space-y-1">
            {incident.related_logs.map(log => (
              <div key={log.event_id} className={`severity-row-${log.severity} px-2 py-1 bg-bg-main rounded`}>
                <span className="text-text-secondary">{formatTime(log.timestamp)}</span> {log.message}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
