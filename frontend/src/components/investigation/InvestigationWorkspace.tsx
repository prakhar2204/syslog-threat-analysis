import { useState } from 'react';
import type { Incident, IncidentInsights, SmartRecommendation, Severity } from '../../types';
import { formatTime } from '../../utils/formatters';
import {
  Shield, Target, Zap, AlertTriangle, CheckCircle, ChevronDown, ChevronRight,
  TrendingUp, Brain, FileText, Users, Server, Crosshair, Link2,
} from 'lucide-react';

function SevBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    CRITICAL: 'bg-severity-critical text-white',
    HIGH: 'bg-severity-high text-white',
    MEDIUM: 'bg-severity-medium text-black',
    LOW: 'bg-severity-low text-white',
    INFO: 'bg-severity-info text-white',
  };
  return <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${cls[s] || 'bg-gray-500 text-white'}`}>{s}</span>;
}

/* ---- Attack Chain Visualization ---- */
export function AttackChainViz({ insights }: { insights: IncidentInsights }) {
  const chain = insights.attack_chain;
  if (!chain.chain_id) return null;

  const allStages = [...chain.stages_completed, ...chain.stages_missing];
  // Reconstruct order: completed first by their natural order, then missing
  const stageOrder = ['recon', 'brute_force', 'enumeration', 'credential_success', 'exploitation',
    'privilege_escalation', 'data_access', 'persistence', 'exfiltration',
    'probing', 'resource_exhaustion', 'service_crash', 'denial_of_service'];
  const ordered = stageOrder.filter(s => allStages.includes(s));

  return (
    <div className="bg-bg-card border border-border rounded p-4">
      <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
        <Link2 size={14} className="text-severity-high" /> Attack Chain
        <span className="ml-auto text-[10px] font-mono text-text-secondary">{chain.chain_id}</span>
      </div>
      {/* Progress bar */}
      <div className="mb-3">
        <div className="flex items-center justify-between text-[10px] mb-1">
          <span className="text-text-secondary">Progress</span>
          <span className={`font-semibold ${chain.progress >= 60 ? 'text-severity-critical' : chain.progress >= 30 ? 'text-severity-high' : 'text-primary'}`}>
            {chain.progress}%
          </span>
        </div>
        <div className="w-full h-2 bg-bg-main rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${chain.progress >= 60 ? 'bg-severity-critical' : chain.progress >= 30 ? 'bg-severity-high' : 'bg-primary'}`}
            style={{ width: `${chain.progress}%` }}
          />
        </div>
      </div>
      {/* Stage pipeline */}
      <div className="flex items-center gap-1 mb-3 overflow-x-auto pb-1">
        {ordered.map((stage, i) => {
          const completed = chain.stages_completed.includes(stage);
          const isCurrent = stage === insights.attack_chain.stage;
          const isClickable = completed || isCurrent;
          return (
            <div key={stage} className="flex items-center gap-1 shrink-0">
              {i > 0 && <div className={`w-4 h-0.5 ${completed ? 'bg-severity-critical' : 'bg-border'}`} />}
              <div
                role={isClickable ? 'button' : undefined}
                tabIndex={isClickable ? 0 : undefined}
                onClick={isClickable ? () => {
                  document.getElementById('evidence-section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                } : undefined}
                title={isClickable ? 'Jump to evidence' : undefined}
                className={`px-2 py-1 rounded text-[9px] font-medium border transition
                ${isCurrent ? 'border-severity-high bg-severity-high/10 text-severity-high ring-1 ring-severity-high/30 cursor-pointer hover:bg-severity-high/20' :
                  completed ? 'border-severity-critical/30 bg-severity-critical/10 text-severity-critical cursor-pointer hover:bg-severity-critical/20' :
                  'border-border bg-bg-main text-text-secondary cursor-default'}`}>
                {completed && <CheckCircle size={8} className="inline mr-0.5" />}
                {stage.replace(/_/g, ' ')}
              </div>
            </div>
          );
        })}
      </div>

      {/* Objective */}
      <div className="text-[10px] text-text-secondary">
        <span className="font-semibold text-text-primary">Objective:</span> {chain.estimated_objective}
      </div>
    </div>
  );
}

/* ---- Threat Score Breakdown ---- */
export function ThreatScoreBreakdown({ insights }: { insights: IncidentInsights }) {
  const bd = insights.threat_score_breakdown;
  if (!bd || Object.keys(bd).length === 0) return null;

  const factors = [
    { key: 'rule_severity', label: 'Rule Severity', weight: 0.15 },
    { key: 'evidence_quality', label: 'Evidence Quality', weight: 0.12 },
    { key: 'correlation_strength', label: 'Correlation', weight: 0.12 },
    { key: 'attack_stage', label: 'Attack Stage', weight: 0.10 },
    { key: 'time_density', label: 'Time Density', weight: 0.10 },
    { key: 'rule_diversity', label: 'Rule Diversity', weight: 0.10 },
    { key: 'ioc_quality', label: 'IOC Quality', weight: 0.08 },
    { key: 'attack_progress', label: 'Chain Progress', weight: 0.08 },
    { key: 'source_diversity', label: 'Source Diversity', weight: 0.08 },
    { key: 'event_volume', label: 'Event Volume', weight: 0.07 },
  ];

  const scoreColor = insights.threat_score >= 70 ? 'text-severity-critical' :
    insights.threat_score >= 50 ? 'text-severity-high' :
    insights.threat_score >= 30 ? 'text-severity-medium' : 'text-primary';

  return (
    <div className="bg-bg-card border border-border rounded p-4">
      <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
        <TrendingUp size={14} className="text-severity-high" /> Threat Score
        <span className={`ml-auto text-lg font-bold ${scoreColor}`}>{insights.threat_score}</span>
        <span className="text-[10px] text-text-secondary">/100</span>
      </div>
      <div className="text-[10px] text-text-secondary mb-2">Priority: <span className="font-bold text-primary">#{insights.priority}</span> in SOC Queue</div>
      <div className="space-y-1.5">
        {factors.map(f => {
          const val = bd[f.key] ?? 0;
          const contribution = val * f.weight;
          return (
            <div key={f.key} className="flex items-center gap-2 text-[10px]">
              <span className="w-24 text-text-secondary truncate">{f.label}</span>
              <div className="flex-1 h-1.5 bg-bg-main rounded-full overflow-hidden">
                <div className="h-full bg-primary/60 rounded-full" style={{ width: `${val}%` }} />
              </div>
              <span className="w-8 text-right font-mono text-text-primary">{val}</span>
              <span className="w-10 text-right font-mono text-primary">+{contribution.toFixed(1)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---- Behavioural Intelligence ---- */
export function BehaviouralPanel({ findings }: { findings: string[] }) {
  if (!findings || findings.length === 0) return null;
  return (
    <div className="bg-bg-card border border-border rounded p-4">
      <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-2">
        <Brain size={14} className="text-severity-high" /> Behavioural Analysis
        <span className="text-[10px] text-text-secondary font-normal ml-auto">{findings.length} findings</span>
      </div>
      <div className="space-y-1.5">
        {findings.map((f, i) => (
          <div key={i} className="flex items-start gap-2 text-xs text-text-primary bg-bg-main rounded p-2 border border-border">
            <AlertTriangle size={11} className="text-severity-high shrink-0 mt-0.5" />
            {f}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---- Root Cause Workspace ---- */
export function RootCauseWorkspace({ insights }: { insights: IncidentInsights }) {
  const [open, setOpen] = useState<Set<string>>(new Set(['exec', 'root', 'narrative']));
  const toggle = (k: string) => setOpen(prev => { const n = new Set(prev); n.has(k) ? n.delete(k) : n.add(k); return n; });

  const Section = ({ id, title, icon, children }: { id: string; title: string; icon: React.ReactNode; children: React.ReactNode }) => (
    <div className="border border-border rounded">
      <button onClick={() => toggle(id)} className="w-full flex items-center gap-2 px-3 py-2 hover:bg-bg-main transition text-left">
        {open.has(id) ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
        {icon}
        <span className="text-[10px] font-semibold text-text-primary">{title}</span>
      </button>
      {open.has(id) && <div className="border-t border-border p-3 text-xs text-text-primary whitespace-pre-line">{children}</div>}
    </div>
  );

  return (
    <div className="bg-bg-card border border-border rounded p-4">
      <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
        <Crosshair size={14} className="text-severity-critical" /> Investigation Insights
      </div>
      <div className="space-y-1.5">
        <Section id="exec" title="Executive Summary" icon={<FileText size={10} className="text-primary" />}>
          {insights.executive_summary || 'No summary available.'}
        </Section>
        <Section id="root" title="Root Cause Analysis" icon={<Crosshair size={10} className="text-severity-critical" />}>
          {insights.root_cause || 'No root cause analysis available.'}
        </Section>
        <Section id="narrative" title="Attack Narrative" icon={<FileText size={10} className="text-severity-high" />}>
          {insights.attack_narrative || 'No narrative available.'}
        </Section>
        <Section id="tech" title="Technical Summary" icon={<Server size={10} className="text-text-secondary" />}>
          {insights.technical_summary || 'No technical summary available.'}
        </Section>
        {insights.affected_assets.length > 0 && (
          <Section id="assets" title={`Affected Assets (${insights.affected_assets.length})`} icon={<Target size={10} className="text-severity-high" />}>
            <div className="space-y-1">
              {insights.affected_assets.map((a, i) => (
                <div key={i} className="flex items-center gap-2 text-[11px] font-mono bg-bg-main rounded px-2 py-1 border border-border">{a}</div>
              ))}
            </div>
          </Section>
        )}
        {insights.mitre_summary && (
          <Section id="mitre" title="MITRE ATT&CK Summary" icon={<Shield size={10} className="text-primary" />}>
            {insights.mitre_summary}
          </Section>
        )}
      </div>
    </div>
  );
}

/* ---- Smart Recommendations ---- */
export function SmartRecommendationsPanel({ recs }: { recs: SmartRecommendation[] }) {
  if (!recs || recs.length === 0) return null;
  const [statuses, setStatuses] = useState<Record<number, string>>({});

  const priColor: Record<string, string> = {
    CRITICAL: 'bg-severity-critical text-white',
    HIGH: 'bg-severity-high text-white',
    MEDIUM: 'bg-severity-medium text-black',
  };

  const cycleStatus = (i: number) => {
    const order = ['pending', 'in_progress', 'completed'];
    const current = statuses[i] || 'pending';
    const next = order[(order.indexOf(current) + 1) % order.length];
    setStatuses(prev => ({ ...prev, [i]: next }));
  };

  const statusStyle: Record<string, string> = {
    pending: 'bg-bg-main text-text-secondary',
    in_progress: 'bg-primary/10 text-primary',
    completed: 'bg-severity-info/10 text-severity-info',
  };

  return (
    <div className="bg-bg-card border border-border rounded p-4">
      <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
        <Zap size={14} className="text-severity-high" /> Analyst Actions
        <span className="text-[10px] text-text-secondary font-normal ml-auto">{recs.length} recommendations</span>
      </div>
      <div className="space-y-2">
        {recs.map((rec, i) => {
          const st = statuses[i] || 'pending';
          return (
            <div key={i} className="border border-border rounded p-2.5 hover:shadow-sm transition">
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-[9px] px-1.5 py-0.5 rounded font-medium ${priColor[rec.priority] || 'bg-bg-main text-text-secondary'}`}>
                  {rec.priority}
                </span>
                <span className="text-[11px] font-medium text-text-primary flex-1">{rec.action}</span>
                <button onClick={() => cycleStatus(i)} className={`text-[9px] px-2 py-0.5 rounded font-medium cursor-pointer ${statusStyle[st]}`}>
                  {st.replace('_', ' ')}
                </button>
              </div>
              <div className="grid grid-cols-2 gap-x-4 text-[10px] text-text-secondary">
                <div><span className="font-medium">Reason:</span> {rec.reason}</div>
                <div><span className="font-medium">Impact:</span> {rec.impact}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
