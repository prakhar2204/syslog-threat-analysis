import { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import StatsCards from '../components/dashboard/StatsCards';
import LogStream from '../components/dashboard/LogStream';
import AlertPanel from '../components/dashboard/AlertPanel';
import DashboardCharts from '../components/charts/DashboardCharts';
import IncidentList from '../components/dashboard/IncidentList';
import type { DashboardStats, LogFile, MonitoringStatus, Alert, Incident } from '../types';
import { Play, Square } from 'lucide-react';

export default function Dashboard() {
  const { state, dispatch } = useApp();
  const [files, setFiles] = useState<LogFile[]>([]);
  const [selected, setSelected] = useState('');
  const [monitorStatus, setMonitorStatus] = useState<MonitoringStatus | null>(null);

  useEffect(() => {
    api.getFiles().then(setFiles).catch(() => {});
    api.getMonitorStatus().then(setMonitorStatus).catch(() => {});

    // Load initial data via REST if WebSocket hasn't populated yet
    api.getStats().then((s: DashboardStats) => {
      if (!state.stats) dispatch({ type: 'SET_STATS', payload: s });
    }).catch(() => {});

    api.getAlerts().then((alerts: Alert[]) => {
      if (state.alerts.length === 0) {
        alerts.forEach(a => dispatch({ type: 'ADD_ALERT', payload: a }));
      }
    }).catch(() => {});

    api.getIncidents().then((incidents: Incident[]) => {
      if (state.incidents.length === 0) {
        incidents.forEach(i => dispatch({ type: 'ADD_INCIDENT', payload: i }));
      }
    }).catch(() => {});
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const startMonitor = async () => {
    if (!selected) return;
    try {
      await api.startMonitor(selected);
      setMonitorStatus({ active: true, file_path: selected, lines_processed: 0, last_event_time: null });
    } catch (err) {
      console.error('Failed to start monitor:', err);
    }
  };

  const stopMonitor = async () => {
    try {
      await api.stopMonitor();
      setMonitorStatus(prev => prev ? { ...prev, active: false } : null);
    } catch (err) {
      console.error('Failed to stop monitor:', err);
    }
  };

  return (
    <div className="space-y-3">
      {/* Monitor Controls */}
      <div className="bg-bg-card border border-border rounded px-3 py-2 flex items-center gap-3">
        <select
          value={selected}
          onChange={e => setSelected(e.target.value)}
          className="text-xs border border-border rounded px-2 py-1.5 bg-white flex-1 max-w-xs"
        >
          <option value="">Select log file…</option>
          {files.map(f => (
            <option key={f.path} value={f.path}>{f.name} ({(f.size_bytes / 1024).toFixed(1)} KB)</option>
          ))}
        </select>
        {monitorStatus?.active ? (
          <button onClick={stopMonitor} className="flex items-center gap-1.5 text-xs bg-severity-critical text-white px-3 py-1.5 rounded hover:opacity-90 transition">
            <Square size={12} /> Stop
          </button>
        ) : (
          <button onClick={startMonitor} className="flex items-center gap-1.5 text-xs bg-primary text-white px-3 py-1.5 rounded hover:opacity-90 transition" disabled={!selected}>
            <Play size={12} /> Start Monitoring
          </button>
        )}
        {monitorStatus?.active && (
          <span className="text-[10px] text-text-secondary flex items-center gap-1">
            <span className="w-2 h-2 bg-severity-info rounded-full animate-pulse" />
            Monitoring {monitorStatus.file_path.split(/[/\\]/).pop()}
          </span>
        )}
      </div>

      <StatsCards stats={state.stats} />

      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2">
          <LogStream logs={state.logs} />
        </div>
        <div>
          <IncidentList incidents={state.incidents} />
        </div>
      </div>

      <AlertPanel alerts={state.alerts} />
      <DashboardCharts stats={state.stats} />
    </div>
  );
}
