import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import type { Incident, Severity, Evidence, RawLogRef } from '../types';
import { formatTime, formatDateTime } from '../utils/formatters';
import { ArrowLeft, Clock, Shield, AlertTriangle, CheckCircle, XCircle, Search, FileText, ChevronDown, ChevronRight } from 'lucide-react';

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

/* ---------- Incident List Page ---------- */
export default function Incidents() {
  const { state } = useApp();
  const nav = useNavigate();
  const [incidents, setIncidents] = useState<Incident[]>([]);

  useEffect(() => {
    api.getIncidents().then(setIncidents).catch(() => {});
  }, [state.incidents.length]);

  return (
    <div className="space-y-3">
      <div className="text-sm font-semibold text-text-primary">Incidents</div>
      {incidents.length === 0 ? (
        <div className="bg-bg-card border border-border rounded p-6 text-center text-xs text-text-secondary">No incidents detected yet.</div>
      ) : (
        <div className="space-y-2">
          {incidents.map(inc => (
            <div
              key={inc.incident_id}
              onClick={() => nav(`/incidents/${inc.incident_id}`)}
              className="bg-bg-card border border-border rounded p-3 hover:bg-bg-main cursor-pointer transition-colors"
            >
              <div className="flex items-center gap-3">
                <SevBadge s={inc.severity} />
                <span className="text-xs font-medium text-text-primary flex-1">{inc.incident_type}</span>
                <span className="text-[10px] text-primary font-medium">{inc.confidence}% confidence</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded border border-border text-text-secondary">{inc.risk}</span>
                <span className="text-[10px] text-text-secondary">{inc.status}</span>
              </div>
              <div className="flex items-center gap-4 mt-1.5 text-[10px] text-text-secondary">
                <span>ID: {inc.incident_id.slice(0, 8)}</span>
                <span>IPs: {inc.source_ips.join(', ') || '—'}</span>
                <span>User: {inc.target_user || '—'}</span>
                <span>{inc.total_events} events</span>
                <span>First: {formatTime(inc.first_seen)}</span>
                <span>Last: {formatTime(inc.last_seen)}</span>
              </div>
            </div>
          ))}
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
            <pre className="text-[10px] font-mono text-text-primary whitespace-pre-wrap bg-white p-2 rounded border border-border">{logRef.raw_log}</pre>
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
      <div className="bg-bg-card border border-border rounded p-4">
        <div className="flex items-center gap-3">
          <SevBadge s={incident.severity} />
          <span className="text-sm font-semibold text-text-primary">{incident.incident_type}</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded border border-border text-text-secondary">{incident.status}</span>
        </div>
        <div className="grid grid-cols-4 gap-3 mt-3 text-xs">
          <div><span className="text-text-secondary">Incident ID:</span><br /><span className="font-mono">{incident.incident_id}</span></div>
          <div><span className="text-text-secondary">Confidence:</span><br /><span className="text-primary font-semibold">{incident.confidence}%</span></div>
          <div><span className="text-text-secondary">Risk Level:</span><br />{incident.risk}</div>
          <div><span className="text-text-secondary">Total Events:</span><br />{incident.total_events}</div>
          <div><span className="text-text-secondary">Source IPs:</span><br /><span className="font-mono">{incident.source_ips.join(', ') || '—'}</span></div>
          <div><span className="text-text-secondary">Target User:</span><br />{incident.target_user || '—'}</div>
          <div><span className="text-text-secondary">First Seen:</span><br />{formatDateTime(incident.first_seen)}</div>
          <div><span className="text-text-secondary">Last Seen:</span><br />{formatDateTime(incident.last_seen)}</div>
        </div>
      </div>

      {/* ===== EVIDENCE PANEL (FIRST SECTION) ===== */}
      {evidence && (
        <div className="bg-bg-card border border-border rounded p-4">
          <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
            <Search size={14} className="text-primary" /> Evidence
            <span className="text-[10px] text-text-secondary font-normal ml-auto">
              {evidence.evidence_id} · {evidence.collection_confidence.toFixed(0)}% confidence
            </span>
          </div>

          {/* Evidence Summary */}
          <div className="grid grid-cols-4 gap-3 mb-3 text-xs">
            <div><span className="text-text-secondary">Matched Rule:</span><br /><span className="font-medium">{evidence.rule_name}</span></div>
            <div><span className="text-text-secondary">Primary Source IP:</span><br /><span className="font-mono">{evidence.source_ips[0] || '-'}</span></div>
            <div><span className="text-text-secondary">Primary Username:</span><br />{evidence.usernames[0] || '-'}</div>
            <div><span className="text-text-secondary">Affected Service:</span><br />{evidence.services[0] || '-'}</div>
            <div><span className="text-text-secondary">Time Window:</span><br />{formatTime(evidence.first_seen)} - {formatTime(evidence.last_seen)}</div>
            <div><span className="text-text-secondary">Evidence Count:</span><br />{evidence.event_count} events</div>
            <div><span className="text-text-secondary">Raw Log Count:</span><br />{evidence.raw_log_refs.length}</div>
            <div><span className="text-text-secondary">Related Alerts:</span><br />{evidence.related_alert_ids.length}</div>
          </div>

          {/* Matched Conditions */}
          {evidence.matched_conditions.length > 0 && (
            <div className="mb-3">
              <div className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider mb-1.5">Matched Conditions</div>
              <div className="grid grid-cols-2 gap-1">
                {evidence.matched_conditions.map((cond, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    {cond.matched ? (
                      <CheckCircle size={12} className="text-severity-info shrink-0" />
                    ) : (
                      <XCircle size={12} className="text-severity-critical shrink-0" />
                    )}
                    <span className="text-text-primary">{cond.condition}</span>
                    {cond.value && <span className="text-text-secondary font-mono text-[10px]">{cond.value}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Extracted IOCs */}
          {evidence.extracted_iocs.length > 0 && (
            <div className="mb-3">
              <div className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider mb-1.5">Extracted IOCs</div>
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
            </div>
          )}

          {/* Raw Log Viewer */}
          {evidence.raw_log_refs.length > 0 && (
            <div>
              <div className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider mb-1.5 flex items-center gap-1">
                <FileText size={10} /> Raw Logs ({evidence.raw_log_refs.length})
              </div>
              <div className="space-y-1 max-h-64 overflow-y-auto">
                {evidence.raw_log_refs.map(ref => (
                  <RawLogViewer key={ref.event_id} logRef={ref} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Reasoning */}
      <div className="bg-bg-card border border-border rounded p-4">
        <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-2">
          <Shield size={14} className="text-primary" /> Analysis & Reasoning
        </div>
        <div className="text-xs text-text-primary leading-relaxed whitespace-pre-line">{incident.reasoning || 'No reasoning available.'}</div>
        {incident.correlation_explanation && (
          <div className="mt-2 text-xs text-text-secondary italic">{incident.correlation_explanation}</div>
        )}
      </div>

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

      {/* Timeline */}
      {incident.timeline.length > 0 && (
        <div className="bg-bg-card border border-border rounded p-4">
          <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
            <Clock size={14} className="text-primary" /> Incident Timeline
          </div>
          <div className="relative pl-4 border-l-2 border-border space-y-3">
            {incident.timeline.map((evt, i) => (
              <div key={i} className="relative">
                <div className={`absolute -left-[21px] w-2.5 h-2.5 rounded-full border-2 border-bg-card`}
                  style={{ backgroundColor: evt.severity === 'CRITICAL' ? '#dc3545' : evt.severity === 'HIGH' ? '#e67700' : '#1a73e8' }}
                />
                <div className="text-[10px] text-text-secondary font-mono">{formatTime(evt.timestamp)}</div>
                <div className="text-xs text-text-primary">{evt.description}</div>
              </div>
            ))}
          </div>
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
