/* SysLog Threat Analysis — Detection Explanation Panel */

import { HelpCircle, CheckCircle, XCircle, Shield, AlertTriangle } from 'lucide-react';
import type { Evidence, Incident } from '../../types';

interface Props {
  incident: Incident;
  evidence: Evidence | null;
}

export default function DetectionExplanation({ incident, evidence }: Props) {
  return (
    <div className="bg-bg-card border border-border rounded p-4">
      <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
        <HelpCircle size={14} className="text-primary" />
        Why Was This Detected?
      </div>

      {/* Detection reasoning */}
      <div className="space-y-3">
        {/* Matched conditions from evidence */}
        {evidence && evidence.matched_conditions.length > 0 && (
          <div>
            <div className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider mb-1.5">
              Detection Conditions
            </div>
            <div className="space-y-1">
              {evidence.matched_conditions.map((cond, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  {cond.matched ? (
                    <CheckCircle size={12} className="text-severity-info shrink-0" />
                  ) : (
                    <XCircle size={12} className="text-severity-critical shrink-0" />
                  )}
                  <span className="text-text-primary">{cond.condition}</span>
                  {cond.value && (
                    <span className="text-text-secondary font-mono text-[10px] bg-bg-main px-1 rounded">{cond.value}</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Correlation rule */}
        {incident.correlation_explanation && (
          <div>
            <div className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider mb-1">
              Correlation Rule
            </div>
            <div className="text-xs text-text-primary bg-bg-main rounded p-2 border border-border">
              {incident.correlation_explanation}
            </div>
          </div>
        )}

        {/* Triggered rules */}
        {incident.triggered_rules.length > 0 && (
          <div>
            <div className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider mb-1">
              Triggered Detection Rules
            </div>
            <div className="flex flex-wrap gap-1">
              {incident.triggered_rules.map(r => (
                <span key={r} className="text-[10px] px-1.5 py-0.5 rounded bg-primary/10 text-primary font-mono border border-primary/20">
                  {r}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Confidence breakdown */}
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-bg-main rounded p-2 border border-border">
            <div className="text-[9px] text-text-secondary uppercase">Confidence</div>
            <div className="text-sm font-bold text-primary">{incident.confidence}%</div>
          </div>
          <div className="bg-bg-main rounded p-2 border border-border">
            <div className="text-[9px] text-text-secondary uppercase">Risk Level</div>
            <div className="text-sm font-bold text-text-primary flex items-center gap-1">
              <AlertTriangle size={12} className="text-severity-critical" /> {incident.risk}
            </div>
          </div>
          {evidence && (
            <div className="bg-bg-main rounded p-2 border border-border">
              <div className="text-[9px] text-text-secondary uppercase">Evidence Confidence</div>
              <div className="text-sm font-bold text-primary">{evidence.collection_confidence.toFixed(0)}%</div>
            </div>
          )}
        </div>

        {/* Reasoning */}
        {incident.reasoning && (
          <div>
            <div className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider mb-1 flex items-center gap-1">
              <Shield size={10} /> Analysis
            </div>
            <div className="text-xs text-text-primary leading-relaxed whitespace-pre-line">{incident.reasoning}</div>
          </div>
        )}
      </div>
    </div>
  );
}
