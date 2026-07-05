/* SysLog Threat Analysis — Formatting Utilities */

import type { Severity } from '../types';

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#dc3545',
  HIGH: '#e67700',
  MEDIUM: '#ffc107',
  LOW: '#0d6efd',
  INFO: '#198754',
};

export const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: 'bg-severity-critical',
  HIGH: 'bg-severity-high',
  MEDIUM: 'bg-severity-medium',
  LOW: 'bg-severity-low',
  INFO: 'bg-severity-info',
};

export function formatTime(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour12: false });
}

export function formatDateTime(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max) + '…';
}
