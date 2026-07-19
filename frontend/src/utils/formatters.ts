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

/** Format ISO timestamp to local time string (HH:MM:SS) */
export function formatTime(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour12: false });
}

/** Format ISO timestamp to full local date-time */
export function formatDateTime(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

/** Format ISO timestamp as relative time ("2 min ago", "1h ago", "just now") */
export function relativeTime(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const now = Date.now();
  const diff = Math.max(0, now - d.getTime());
  const seconds = Math.floor(diff / 1000);

  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

/** Format timestamp with mode: 'absolute' (HH:MM:SS) or 'relative' (Xm ago) */
export function formatTimestamp(iso: string, mode: 'absolute' | 'relative' = 'absolute'): string {
  return mode === 'relative' ? relativeTime(iso) : formatTime(iso);
}

/** Compute duration string between two ISO timestamps */
export function formatDuration(startIso: string, endIso: string): string {
  if (!startIso || !endIso) return '—';
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime();
  const seconds = Math.floor(Math.abs(ms) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
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
