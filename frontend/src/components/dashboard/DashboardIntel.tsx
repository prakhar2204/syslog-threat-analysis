import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import type { DashboardIntelligence } from '../../types';
import {
  Shield, Target, User, Server, Fingerprint, Link2, Brain,
  TrendingUp, ArrowRight, AlertTriangle, Activity, Hash,
} from 'lucide-react';

export default function DashboardIntel() {
  const [intel, setIntel] = useState<DashboardIntelligence | null>(null);
  const nav = useNavigate();

  useEffect(() => {
    const load = () => api.getDashboardIntelligence().then(setIntel).catch(() => {});
    load();
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  }, []);

  if (!intel) return null;

  const sevColor: Record<string, string> = {
    CRITICAL: 'text-severity-critical', HIGH: 'text-severity-high',
    MEDIUM: 'text-severity-medium', LOW: 'text-severity-low',
  };

  return (
    <div className="space-y-3">
      {/* Top intelligence cards */}
      <div className="grid grid-cols-5 gap-2">
        {/* Most Dangerous Attack */}
        <div className="bg-bg-card border border-border rounded p-3">
          <div className="text-[9px] uppercase text-text-secondary font-semibold mb-1 flex items-center gap-1">
            <AlertTriangle size={9} className="text-severity-critical" /> Most Dangerous
          </div>
          {intel.most_dangerous_attack ? (
            <>
              <div className={`text-lg font-bold ${sevColor[intel.most_dangerous_attack.severity] || 'text-text-primary'}`}>
                {intel.most_dangerous_attack.threat_score.toFixed(0)}
              </div>
              <div className="text-[10px] text-text-primary truncate">{intel.most_dangerous_attack.type}</div>
              <button onClick={() => nav(`/incidents/${intel.most_dangerous_attack!.incident_id}`)}
                className="text-[9px] text-primary hover:underline mt-0.5 flex items-center gap-0.5">
                Investigate <ArrowRight size={8} />
              </button>
            </>
          ) : <div className="text-[10px] text-text-secondary">No threats</div>}
        </div>

        {/* Top Attacker */}
        <div className="bg-bg-card border border-border rounded p-3">
          <div className="text-[9px] uppercase text-text-secondary font-semibold mb-1 flex items-center gap-1">
            <Target size={9} className="text-severity-high" /> Top Attacker
          </div>
          {intel.most_active_attacker ? (
            <>
              <div className="text-sm font-bold font-mono text-text-primary">{intel.most_active_attacker.ip}</div>
              <div className="text-[10px] text-text-secondary">{intel.most_active_attacker.event_count} events</div>
            </>
          ) : <div className="text-[10px] text-text-secondary">—</div>}
        </div>

        {/* Most Targeted User */}
        <div className="bg-bg-card border border-border rounded p-3">
          <div className="text-[9px] uppercase text-text-secondary font-semibold mb-1 flex items-center gap-1">
            <User size={9} className="text-severity-high" /> Targeted User
          </div>
          {intel.most_targeted_user ? (
            <>
              <div className="text-sm font-bold text-text-primary">{intel.most_targeted_user.user}</div>
              <div className="text-[10px] text-text-secondary">{intel.most_targeted_user.event_count} events</div>
            </>
          ) : <div className="text-[10px] text-text-secondary">—</div>}
        </div>

        {/* Most Targeted Service */}
        <div className="bg-bg-card border border-border rounded p-3">
          <div className="text-[9px] uppercase text-text-secondary font-semibold mb-1 flex items-center gap-1">
            <Server size={9} className="text-primary" /> Targeted Service
          </div>
          {intel.most_targeted_service ? (
            <>
              <div className="text-sm font-bold text-text-primary">{intel.most_targeted_service.service}</div>
              <div className="text-[10px] text-text-secondary">{intel.most_targeted_service.event_count} alerts</div>
            </>
          ) : <div className="text-[10px] text-text-secondary">—</div>}
        </div>

        {/* Incident summary */}
        <div className="bg-bg-card border border-border rounded p-3">
          <div className="text-[9px] uppercase text-text-secondary font-semibold mb-1 flex items-center gap-1">
            <Activity size={9} className="text-primary" /> Investigations
          </div>
          <div className="text-lg font-bold text-text-primary">{intel.total_incidents}</div>
          <div className="text-[10px] text-text-secondary">{intel.merged_incidents} merged</div>
        </div>
      </div>

      {/* SOC Queue + Attack Chains + Behaviour + Top IOCs */}
      <div className="grid grid-cols-4 gap-3">
        {/* SOC Priority Queue */}
        <div className="bg-bg-card border border-border rounded p-3">
          <div className="text-[10px] font-semibold text-text-primary flex items-center gap-1 mb-2">
            <TrendingUp size={11} className="text-severity-high" /> SOC Queue
          </div>
          <div className="space-y-1">
            {intel.soc_queue.slice(0, 6).map(q => (
              <button key={q.incident_id} onClick={() => nav(`/incidents/${q.incident_id}`)}
                className="w-full flex items-center gap-2 text-[10px] p-1.5 rounded hover:bg-bg-main transition text-left">
                <span className="w-4 h-4 rounded-full bg-primary/10 text-primary text-[9px] font-bold flex items-center justify-center shrink-0">
                  {q.priority}
                </span>
                <span className="flex-1 truncate text-text-primary">{q.type}</span>
                <span className={`font-mono font-semibold ${sevColor[q.severity] || ''}`}>{q.threat_score.toFixed(0)}</span>
              </button>
            ))}
            {intel.soc_queue.length === 0 && <div className="text-[10px] text-text-secondary">No active incidents</div>}
          </div>
        </div>

        {/* Attack Chains */}
        <div className="bg-bg-card border border-border rounded p-3">
          <div className="text-[10px] font-semibold text-text-primary flex items-center gap-1 mb-2">
            <Link2 size={11} className="text-severity-critical" /> Attack Campaigns
          </div>
          {intel.attack_chains.length === 0 ? (
            <div className="text-[10px] text-text-secondary">No active chains</div>
          ) : (
            <div className="space-y-2">
              {intel.attack_chains.slice(0, 4).map(c => (
                <div key={c.chain_id} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <div className="text-[10px] text-text-primary font-medium truncate flex-1">{c.chain_name}</div>
                    <span className="text-[9px] font-mono text-text-secondary ml-1">{c.progress}%</span>
                  </div>
                  <div className="h-1.5 bg-bg-main rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${c.progress >= 60 ? 'bg-severity-critical' : c.progress >= 30 ? 'bg-severity-high' : 'bg-primary'}`}
                      style={{ width: `${c.progress}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Behaviour Findings — with supporting data */}
        <div className="bg-bg-card border border-border rounded p-3">
          <div className="text-[10px] font-semibold text-text-primary flex items-center gap-1 mb-2">
            <Brain size={11} className="text-severity-high" /> Behaviour Intel
          </div>
          <div className="space-y-1.5 max-h-40 overflow-y-auto">
            {intel.behaviour_findings.slice(0, 8).map((f, i) => (
              <div key={i} className="text-[10px] bg-bg-main rounded px-1.5 py-1 border border-border space-y-0.5">
                <div className="flex items-start gap-1">
                  <AlertTriangle size={8} className="text-severity-high shrink-0 mt-0.5" />
                  <span className="text-text-primary leading-snug">{f.description}</span>
                </div>
                {/* Supporting data */}
                <div className="flex flex-wrap gap-1 pl-3">
                  {f.ip && <span className="text-[9px] font-mono text-text-secondary">{f.ip}</span>}
                  {f.user && <span className="text-[9px] font-mono text-text-secondary">{f.user}</span>}
                  {f.event_count && (
                    <span className="text-[9px] text-text-secondary flex items-center gap-0.5">
                      <Hash size={7} />{f.event_count}
                    </span>
                  )}
                  {f.targets && (
                    <span className="text-[9px] text-text-secondary">{f.targets} targets</span>
                  )}
                </div>
              </div>
            ))}
            {intel.behaviour_findings.length === 0 && (
              <div className="text-[10px] text-text-secondary">No behaviour findings</div>
            )}
          </div>
        </div>

        {/* Top IOCs — new panel */}
        <div className="bg-bg-card border border-border rounded p-3">
          <div className="text-[10px] font-semibold text-text-primary flex items-center gap-1 mb-2">
            <Fingerprint size={11} className="text-primary" /> Top IOCs
          </div>
          <div className="space-y-1">
            {intel.top_iocs.slice(0, 6).map((ioc, i) => (
              <div key={i} className="flex items-center gap-2 text-[10px] p-1 rounded hover:bg-bg-main transition">
                <span className="text-[9px] px-1 py-0.5 rounded bg-primary/10 text-primary font-medium shrink-0">{ioc.ioc_type}</span>
                <span className="font-mono text-text-primary flex-1 truncate">{ioc.value}</span>
                <span className="text-text-secondary shrink-0">{ioc.occurrences}×</span>
              </div>
            ))}
            {intel.top_iocs.length === 0 && (
              <div className="text-[10px] text-text-secondary">No IOCs collected yet</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
