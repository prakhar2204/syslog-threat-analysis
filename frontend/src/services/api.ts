/* SysLog Threat Analysis - API Client */

import type {
  Alert, DashboardStats, Evidence, Incident, LogDetail, LogFile,
  MonitoringStatus, Observation, PaginatedLogs, PipelineStats,
  SimScenario, SimulationStatus,
} from '../types';

const BASE = import.meta.env.VITE_API_BASE_URL
  ? `${import.meta.env.VITE_API_BASE_URL}/api`
  : '/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

export const api = {
  // -- Stats --
  getStats: () => request<DashboardStats>('/stats'),

  // -- Logs --
  getLogs: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== '' && v !== undefined && v !== null) qs.set(k, String(v));
    });
    return request<PaginatedLogs>(`/logs?${qs}`);
  },
  getLogDetail: (eventId: string) => request<LogDetail>(`/logs/${eventId}`),

  // -- Alerts --
  getAlerts: (status?: string) => {
    const qs = status ? `?status=${status}` : '';
    return request<Alert[]>(`/alerts${qs}`);
  },
  alertAction: (alertId: string, action: 'acknowledge' | 'resolve') =>
    request(`/alerts/action`, {
      method: 'POST',
      body: JSON.stringify({ alert_id: alertId, action }),
    }),

  // -- Incidents --
  getIncidents: () => request<Incident[]>('/incidents'),
  getIncidentDetail: (id: string) => request<Incident>(`/incidents/${id}`),

  // -- Monitoring --
  getMonitorStatus: () => request<MonitoringStatus>('/monitor/status'),
  startMonitor: (filePath?: string, folder?: string, fromBeginning = true) =>
    request('/monitor/start', {
      method: 'POST',
      body: JSON.stringify({ file_path: filePath || '', folder: folder || '', from_beginning: fromBeginning }),
    }),
  stopMonitor: () => request('/monitor/stop', { method: 'POST' }),
  pauseMonitor: () => request('/monitor/pause', { method: 'POST' }),
  resumeMonitor: () => request('/monitor/resume', { method: 'POST' }),
  getSession: () => request('/monitor/session'),
  getSessionHistory: () => request('/monitor/history'),
  getPipelineStats: () => request<PipelineStats>('/monitor/pipeline'),

  // -- Simulation --
  getScenarios: () => request<SimScenario[]>('/simulation/scenarios'),
  startSimulation: (scenarios?: string[], speed = 'normal', targetUser = 'admin', randomizeIps = true) =>
    request('/simulation/start', {
      method: 'POST',
      body: JSON.stringify({ scenarios, speed, target_user: targetUser, randomize_ips: randomizeIps }),
    }),
  stopSimulation: () => request('/simulation/stop', { method: 'POST' }),
  resetSimulation: () => request('/simulation/reset', { method: 'POST' }),
  generateOnce: (scenarios?: string[], targetUser = 'admin') =>
    request('/simulation/generate', {
      method: 'POST',
      body: JSON.stringify({ scenarios, target_user: targetUser }),
    }),
  getSimulationStatus: () => request<SimulationStatus>('/simulation/status'),

  // -- Evidence --
  getEvidence: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params) : '';
    return request<Evidence[]>(`/evidence${qs}`);
  },
  getEvidenceById: (id: string) => request<Evidence>(`/evidence/${id}`),
  searchEvidence: (params: Record<string, string>) => {
    const qs = new URLSearchParams(params);
    return request<Evidence[]>(`/evidence/search?${qs}`);
  },
  getEvidenceByIncident: (incidentId: string) => request<Evidence>(`/evidence/by-incident/${incidentId}`),

  // -- Observations --
  getObservations: () => request<Observation[]>('/observations'),
  getObservationById: (id: string) => request<Observation>(`/observations/${id}`),
  promoteObservation: (observationId: string, incidentId = '') =>
    request('/observations/promote', {
      method: 'POST',
      body: JSON.stringify({ observation_id: observationId, incident_id: incidentId }),
    }),

  // -- Files --
  getFiles: () => request<LogFile[]>('/files'),

  // -- Clear --
  clearDashboard: () => request('/clear', { method: 'POST' }),

  // -- Export --
  exportReport: (format: 'json' | 'csv' | 'pdf') => {
    window.open(`${BASE}/export/${format}`, '_blank');
  },
};
