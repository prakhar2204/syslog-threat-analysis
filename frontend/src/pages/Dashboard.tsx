/* SysLog Threat Analysis - Dashboard Page */

import { useEffect, useState, useCallback } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import ActiveThreatCenter from '../components/dashboard/ActiveThreatCenter';
import ThreatSummary from '../components/dashboard/ThreatSummary';
import DashboardIntel from '../components/dashboard/DashboardIntel';
import LogStream from '../components/dashboard/LogStream';
import InvestigationPanel from '../components/dashboard/InvestigationPanel';
import DashboardCharts from '../components/charts/DashboardCharts';
import IncidentList from '../components/dashboard/IncidentList';
import MonitoringSources from '../components/monitoring/MonitoringSources';
import MonitoringStatusWidget from '../components/monitoring/MonitoringStatus';
import PipelineVisualizer from '../components/monitoring/PipelineVisualizer';
import type { DashboardStats, MonitoringStatus, SimulationStatus, PipelineStats, Alert, Incident } from '../types';

export default function Dashboard() {
  const { state, dispatch } = useApp();
  const [monitorStatus, setMonitorStatus] = useState<MonitoringStatus | null>(null);
  const [simStatus, setSimStatus] = useState<SimulationStatus | null>(null);
  const [pipelineStats, setPipelineStats] = useState<PipelineStats | null>(null);

  const refreshStatus = useCallback(() => {
    api.getMonitorStatus().then(setMonitorStatus).catch(() => {});
    api.getSimulationStatus().then(setSimStatus).catch(() => {});
    api.getPipelineStats().then(setPipelineStats).catch(() => {});
  }, []);

  useEffect(() => {
    refreshStatus();

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

    // Poll monitoring status every 3 seconds
    const iv = setInterval(refreshStatus, 3000);
    return () => clearInterval(iv);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="space-y-3">
      {/* 1. Active Threat Center — highest priority */}
      <ActiveThreatCenter incidents={state.incidents} />

      {/* 2. SOC Intelligence */}
      <DashboardIntel />

      {/* 3. Threat Summary metrics */}
      <ThreatSummary />

      {/* 3. Monitoring Sources */}
      <MonitoringSources monitor={monitorStatus} simulation={simStatus} />

      {/* 4. Pipeline + Monitoring Status */}
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2">
          <PipelineVisualizer stats={pipelineStats} />
        </div>
        <div>
          <MonitoringStatusWidget status={monitorStatus} onRefresh={refreshStatus} />
        </div>
      </div>

      {/* 5. Incidents + Log Stream */}
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2">
          <LogStream logs={state.logs} />
        </div>
        <div>
          <IncidentList incidents={state.incidents} />
        </div>
      </div>

      {/* 6. Investigations */}
      <InvestigationPanel />

      {/* 7. Charts */}
      <DashboardCharts stats={state.stats} />
    </div>
  );
}
