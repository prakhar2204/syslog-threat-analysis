/* SysLog Threat Analysis — Active Threat Banner */

import { ShieldAlert, ArrowRight, X } from 'lucide-react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { Incident } from '../../types';
import { formatTime } from '../../utils/formatters';

interface Props {
  incident: Incident | null;
}

export default function ThreatBanner({ incident }: Props) {
  const [dismissed, setDismissed] = useState<string | null>(null);
  const nav = useNavigate();

  if (!incident || incident.incident_id === dismissed) return null;
  if (incident.severity !== 'CRITICAL' && incident.severity !== 'HIGH') return null;

  return (
    <div className="banner-enter bg-severity-critical/10 border-b border-severity-critical/30 px-4 py-2 shrink-0">
      <div className="flex items-center gap-3">
        <ShieldAlert size={16} className="text-severity-critical shrink-0" />
        <span className="text-[10px] font-bold text-severity-critical uppercase tracking-wider">Active Attack Detected</span>
        <span className="text-xs font-semibold text-text-primary">{incident.incident_type}</span>
        <div className="flex items-center gap-3 text-[10px] text-text-secondary ml-auto">
          <span>Source: <span className="font-mono text-text-primary">{incident.source_ips[0] || '—'}</span></span>
          <span>Target: <span className="text-text-primary">{incident.target_user || '—'}</span></span>
          <span>Confidence: <span className="text-primary font-semibold">{incident.confidence}%</span></span>
          {incident.mitre_techniques.length > 0 && (
            <span>MITRE: <span className="font-mono text-primary">{incident.mitre_techniques[0]}</span></span>
          )}
          <span>Started: <span className="font-mono">{formatTime(incident.first_seen)}</span></span>
          <button
            onClick={() => nav(`/incidents/${incident.incident_id}`)}
            className="flex items-center gap-1 text-primary hover:underline font-medium"
          >
            Investigate <ArrowRight size={10} />
          </button>
          <button
            onClick={() => setDismissed(incident.incident_id)}
            className="p-0.5 hover:bg-severity-critical/20 rounded transition"
          >
            <X size={12} className="text-text-secondary" />
          </button>
        </div>
      </div>
    </div>
  );
}
