/* SysLog Threat Analysis — API Client */

import type { Alert, DashboardStats, Incident, LogDetail, LogFile, MonitoringStatus, PaginatedLogs } from '../types';

const BASE = '/api';

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
  getStats: () => request<DashboardStats>('/stats'),

  getLogs: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== '' && v !== undefined && v !== null) qs.set(k, String(v));
    });
    return request<PaginatedLogs>(`/logs?${qs}`);
  },

  getLogDetail: (eventId: string) => request<LogDetail>(`/logs/${eventId}`),

  getAlerts: (status?: string) => {
    const qs = status ? `?status=${status}` : '';
    return request<Alert[]>(`/alerts${qs}`);
  },

  alertAction: (alertId: string, action: 'acknowledge' | 'resolve') =>
    request(`/alerts/action`, {
      method: 'POST',
      body: JSON.stringify({ alert_id: alertId, action }),
    }),

  getIncidents: () => request<Incident[]>('/incidents'),
  getIncidentDetail: (id: string) => request<Incident>(`/incidents/${id}`),

  getMonitorStatus: () => request<MonitoringStatus>('/monitor/status'),

  startMonitor: (filePath: string, fromBeginning = true) =>
    request('/monitor/start', {
      method: 'POST',
      body: JSON.stringify({ file_path: filePath, from_beginning: fromBeginning }),
    }),

  stopMonitor: () => request('/monitor/stop', { method: 'POST' }),

  getFiles: () => request<LogFile[]>('/files'),

  clearDashboard: () => request('/clear', { method: 'POST' }),

  exportReport: (format: 'json' | 'csv' | 'pdf') => {
    window.open(`${BASE}/export/${format}`, '_blank');
  },
};
