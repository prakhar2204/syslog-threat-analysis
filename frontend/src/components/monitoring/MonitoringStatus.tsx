/* SysLog Threat Analysis - Monitoring Status Widget */

import { Activity, Clock, Database, Wifi, Server, FolderOpen, Pause, Play, Square } from 'lucide-react';
import type { MonitoringStatus as MonStatus } from '../../types';
import { api } from '../../services/api';

interface Props {
  status: MonStatus | null;
  onRefresh: () => void;
}

export default function MonitoringStatusWidget({ status, onRefresh }: Props) {
  if (!status) return null;

  const handleStop = async () => { await api.stopMonitor(); onRefresh(); };
  const handlePause = async () => { await api.pauseMonitor(); onRefresh(); };
  const handleResume = async () => { await api.resumeMonitor(); onRefresh(); };
  const handleStart = async () => { await api.startMonitor(); onRefresh(); };

  return (
    <div className="bg-bg-card border border-border rounded p-3">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Activity size={13} className="text-primary" />
          <span className="text-xs font-semibold text-text-primary">Monitoring Status</span>
        </div>
        <div className="flex items-center gap-1.5">
          {status.active ? (
            <>
              <button onClick={handlePause} className="p-1 rounded hover:bg-gray-100 transition" title="Pause">
                <Pause size={12} className="text-severity-medium" />
              </button>
              <button onClick={handleStop} className="p-1 rounded hover:bg-gray-100 transition" title="Stop">
                <Square size={12} className="text-severity-critical" />
              </button>
            </>
          ) : status.paused ? (
            <button onClick={handleResume} className="p-1 rounded hover:bg-gray-100 transition" title="Resume">
              <Play size={12} className="text-severity-info" />
            </button>
          ) : (
            <button onClick={handleStart} className="p-1 rounded hover:bg-gray-100 transition" title="Start">
              <Play size={12} className="text-severity-info" />
            </button>
          )}
        </div>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[10px]">
        <Row icon={<Server size={10} />} label="Mode" value={status.mode || 'idle'} />
        <Row icon={<FolderOpen size={10} />} label="Folder" value={status.folder?.split(/[/\\]/).pop() || '-'} />
        <Row icon={<Database size={10} />} label="Files" value={String(status.files_monitored)} />
        <Row icon={<Activity size={10} />} label="EPS" value={`${status.events_per_second}/s`} />
        <Row icon={<Clock size={10} />} label="Uptime" value={formatUptime(status.watcher_uptime_seconds)} />
        <Row icon={<Wifi size={10} />} label="Lines" value={status.lines_processed.toLocaleString()} />
      </div>
    </div>
  );
}

function Row({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-1.5 text-text-secondary">
      {icon}
      <span>{label}</span>
      <span className="ml-auto text-text-primary font-mono">{value}</span>
    </div>
  );
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
