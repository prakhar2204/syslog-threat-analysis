/* SysLog Threat Analysis - Monitoring Sources Cards */

import { FolderOpen, Crosshair, Archive, Circle } from 'lucide-react';
import type { MonitoringStatus, SimulationStatus } from '../../types';

interface Props {
  monitor: MonitoringStatus | null;
  simulation: SimulationStatus | null;
}

export default function MonitoringSources({ monitor, simulation }: Props) {
  const liveActive = monitor?.active && !monitor?.paused;
  const livePaused = monitor?.paused;
  const simActive = simulation?.active;

  return (
    <div className="grid grid-cols-3 gap-3">
      {/* Live Folder Monitoring */}
      <div className={`bg-bg-card border rounded p-3 ${liveActive ? 'border-severity-info' : livePaused ? 'border-severity-medium' : 'border-border'}`}>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <FolderOpen size={14} className="text-primary" />
            <span className="text-xs font-semibold text-text-primary">Live Monitoring</span>
          </div>
          <StatusDot active={liveActive} paused={livePaused} />
        </div>
        <div className="space-y-1 text-[10px] text-text-secondary">
          <div className="flex justify-between">
            <span>Source</span>
            <span className="text-text-primary font-mono">{monitor?.folder?.split(/[/\\]/).pop() || 'sample_logs/'}</span>
          </div>
          <div className="flex justify-between">
            <span>Events</span>
            <span className="text-text-primary">{monitor?.session?.events_processed ?? 0}</span>
          </div>
          <div className="flex justify-between">
            <span>EPS</span>
            <span className="text-text-primary">{monitor?.events_per_second ?? 0}/s</span>
          </div>
        </div>
      </div>

      {/* Attack Simulator */}
      <div className={`bg-bg-card border rounded p-3 ${simActive ? 'border-severity-critical' : 'border-border'}`}>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Crosshair size={14} className="text-severity-critical" />
            <span className="text-xs font-semibold text-text-primary">Attack Simulator</span>
          </div>
          <StatusDot active={simActive} />
        </div>
        <div className="space-y-1 text-[10px] text-text-secondary">
          <div className="flex justify-between">
            <span>Speed</span>
            <span className="text-text-primary">{simulation?.speed || 'idle'}</span>
          </div>
          <div className="flex justify-between">
            <span>Events</span>
            <span className="text-text-primary">{simulation?.events_generated ?? 0}</span>
          </div>
          <div className="flex justify-between">
            <span>Elapsed</span>
            <span className="text-text-primary">{simulation?.elapsed_seconds ? `${simulation.elapsed_seconds}s` : '-'}</span>
          </div>
        </div>
      </div>

      {/* Historical Investigation */}
      <div className="bg-bg-card border border-border rounded p-3">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Archive size={14} className="text-text-secondary" />
            <span className="text-xs font-semibold text-text-primary">Historical Investigation</span>
          </div>
          <StatusDot active={false} />
        </div>
        <div className="space-y-1 text-[10px] text-text-secondary">
          <div className="flex justify-between">
            <span>Source</span>
            <span className="text-text-primary">-</span>
          </div>
          <div className="flex justify-between">
            <span>Events</span>
            <span className="text-text-primary">-</span>
          </div>
          <div className="flex justify-between">
            <span>Status</span>
            <span className="text-text-primary">Available</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatusDot({ active, paused }: { active?: boolean; paused?: boolean }) {
  if (paused) {
    return (
      <div className="flex items-center gap-1">
        <Circle size={6} className="fill-severity-medium text-severity-medium" />
        <span className="text-[9px] text-severity-medium">Paused</span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-1">
      <Circle size={6} className={active ? 'fill-severity-info text-severity-info animate-pulse' : 'fill-text-secondary/30 text-text-secondary/30'} />
      <span className={`text-[9px] ${active ? 'text-severity-info' : 'text-text-secondary'}`}>
        {active ? 'Active' : 'Stopped'}
      </span>
    </div>
  );
}
