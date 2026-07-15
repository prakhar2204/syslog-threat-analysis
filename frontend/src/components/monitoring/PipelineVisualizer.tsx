/* SysLog Threat Analysis - Pipeline Visualizer */

import { ArrowDown } from 'lucide-react';
import type { PipelineStats } from '../../types';

interface Props {
  stats: PipelineStats | null;
}

const STAGES = [
  { key: 'events_in', label: 'Monitoring', alt: 'logs_buffered' },
  { key: 'events_parsed', label: 'Parser', alt: 'logs_buffered' },
  { key: 'rules_triggered', label: 'Detection', alt: 'alerts_buffered' },
  { key: 'alerts_generated', label: 'Correlation', alt: 'alerts_buffered' },
  { key: 'incidents_generated', label: 'Dashboard', alt: 'incidents_buffered' },
] as const;

export default function PipelineVisualizer({ stats }: Props) {
  return (
    <div className="bg-bg-card border border-border rounded px-3 py-2">
      <div className="text-[10px] font-semibold text-text-secondary mb-2 uppercase tracking-wider">Pipeline</div>
      <div className="flex items-center justify-center gap-1">
        {STAGES.map((stage, i) => {
          const s = stats as unknown as Record<string, number | undefined>;
          const val = stats ? (s[stage.key] ?? s[stage.alt] ?? 0) : 0;
          return (
            <div key={stage.key} className="flex items-center gap-1">
              <div className="text-center">
                <div className="text-[10px] text-text-secondary">{stage.label}</div>
                <div className="text-xs font-mono font-semibold text-text-primary">{val.toLocaleString()}</div>
              </div>
              {i < STAGES.length - 1 && (
                <ArrowDown size={10} className="text-text-secondary/40 rotate-[-90deg] mx-0.5" />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
