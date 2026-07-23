/* SysLog Threat Analysis — Settings Page (Phase 5.6) */

import { useState, useEffect } from 'react';
import { Shield, Database, Bell, Palette, Info, Check, AlertTriangle, RefreshCw } from 'lucide-react';
import { api } from '../services/api';
import { useTheme } from '../context/ThemeContext';
import { useNotifications } from '../context/NotificationContext';

interface SettingsSection {
  id: string;
  label: string;
  icon: typeof Shield;
  description: string;
}

const SECTIONS: SettingsSection[] = [
  { id: 'general', label: 'General', icon: Shield, description: 'Application identity and version' },
  { id: 'monitoring', label: 'Monitoring', icon: Database, description: 'Log monitoring and pipeline configuration' },
  { id: 'notifications', label: 'Notifications', icon: Bell, description: 'Alert and notification preferences' },
  { id: 'appearance', label: 'Appearance', icon: Palette, description: 'Theme and display settings' },
  { id: 'actions', label: 'Actions', icon: AlertTriangle, description: 'Dashboard reset and data management' },
];

export default function SettingsPage() {
  const [active, setActive] = useState('general');
  const [cleared, setCleared] = useState(false);
  const [version, setVersion] = useState<Record<string, string>>({});
  const { mode, setMode } = useTheme();
  const { clearAll: clearNotifications } = useNotifications();

  useEffect(() => {
    fetch(
      (import.meta.env.VITE_API_BASE_URL || '') + '/version'
    )
      .then(r => r.json())
      .then(setVersion)
      .catch(() => {});
  }, []);

  const handleClear = async () => {
    try {
      await api.clearDashboard();
      clearNotifications();
      setCleared(true);
      setTimeout(() => setCleared(false), 3000);
    } catch { /* silent */ }
  };

  return (
    <div className="space-y-3 max-w-3xl">
      <h1 className="text-base font-semibold text-text-primary">Settings</h1>

      {/* Section Tabs */}
      <div className="flex gap-1 bg-bg-card border border-border rounded-lg p-1">
        {SECTIONS.map(s => {
          const Icon = s.icon;
          return (
            <button
              key={s.id}
              onClick={() => setActive(s.id)}
              className={`flex items-center gap-1.5 text-[11px] px-3 py-1.5 rounded transition ${
                active === s.id
                  ? 'bg-primary text-white'
                  : 'text-text-secondary hover:bg-bg-main hover:text-text-primary'
              }`}
            >
              <Icon size={12} />
              {s.label}
            </button>
          );
        })}
      </div>

      {/* Content */}
      <div className="bg-bg-card border border-border rounded-lg p-5">
        {active === 'general' && (
          <div className="space-y-4">
            <SectionHeader title="General" description="Application identity and version information" />
            <SettingRow label="Application" value="SysLog Threat Analysis" />
            <SettingRow label="Version" value={version.version || '1.0.0'} />
            <SettingRow label="Description" value={version.description || 'Real-Time Syslog Monitoring & Threat Detection'} />
            <SettingRow label="Environment" value={version.environment || 'development'} />
            <div className="pt-2 border-t border-border">
              <div className="text-[10px] text-text-secondary/60">
                Offline SIEM-inspired SOC investigation platform with real-time attack detection,
                correlation, and multi-engine intelligence analysis.
              </div>
            </div>
          </div>
        )}

        {active === 'monitoring' && (
          <div className="space-y-4">
            <SectionHeader title="Monitoring Configuration" description="Pipeline and log monitoring settings (configured in backend)" />
            <SettingRow label="Default Log Directory" value="sample_logs/" hint="Configured in backend config.py" />
            <SettingRow label="Maximum Log Buffer" value="100,000 entries" hint="Older entries are automatically trimmed" />
            <SettingRow label="File Poll Interval" value="200ms" hint="How frequently files are checked for new lines" />
            <SettingRow label="Alert Buffer" value="5,000 alerts" />
            <SettingRow label="Incident Buffer" value="1,000 incidents" />
            <div className="pt-2 border-t border-border">
              <div className="flex items-start gap-2 text-[10px] text-text-secondary bg-primary/5 rounded px-3 py-2">
                <Info size={12} className="text-primary shrink-0 mt-0.5" />
                <span>
                  Monitoring settings are managed in the backend configuration file.
                  Changes require a backend restart.
                </span>
              </div>
            </div>
          </div>
        )}

        {active === 'notifications' && (
          <div className="space-y-4">
            <SectionHeader title="Notification Preferences" description="Control which events produce toast popups vs. center entries" />
            <div className="space-y-2">
              <NotifRow label="CRITICAL alerts" desc="Toast popup + Notification Center" enabled />
              <NotifRow label="CRITICAL incidents" desc="Toast popup + Notification Center" enabled />
              <NotifRow label="HIGH alerts" desc="Notification Center only" enabled={false} />
              <NotifRow label="Non-critical incidents" desc="Notification Center only" enabled={false} />
              <NotifRow label="Evidence collected" desc="Notification Center only" enabled={false} />
              <NotifRow label="Observation promoted" desc="Notification Center only" enabled={false} />
            </div>
            <div className="pt-2 border-t border-border">
              <button
                onClick={clearNotifications}
                className="flex items-center gap-1.5 text-[11px] text-text-secondary border border-border px-3 py-1.5 rounded hover:bg-bg-main transition"
              >
                <RefreshCw size={11} /> Clear Notification History
              </button>
            </div>
          </div>
        )}

        {active === 'appearance' && (
          <div className="space-y-4">
            <SectionHeader title="Appearance" description="Theme and display preferences" />
            <div>
              <label className="text-xs font-medium text-text-primary block mb-2">Theme</label>
              <div className="flex gap-2">
                {(['light', 'dark', 'system'] as const).map(m => (
                  <button
                    key={m}
                    onClick={() => setMode(m)}
                    className={`flex items-center gap-1.5 text-[11px] px-4 py-2 rounded border transition ${
                      mode === m
                        ? 'bg-primary text-white border-primary'
                        : 'border-border text-text-secondary hover:border-primary/30'
                    }`}
                  >
                    {m === 'light' && <Palette size={12} />}
                    {m === 'dark' && <Palette size={12} />}
                    {m === 'system' && <Palette size={12} />}
                    {m.charAt(0).toUpperCase() + m.slice(1)}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {active === 'actions' && (
          <div className="space-y-4">
            <SectionHeader title="Dashboard Actions" description="Reset pipeline data and clear the dashboard" />
            <div className="bg-severity-critical/5 border border-severity-critical/20 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle size={16} className="text-severity-critical shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-medium text-text-primary mb-1">Clear All Data</div>
                  <div className="text-[10px] text-text-secondary mb-3">
                    This will clear all logs, alerts, incidents, and evidence from memory.
                    The pipeline will reset. This action cannot be undone.
                  </div>
                  <button
                    onClick={handleClear}
                    className="text-[11px] bg-severity-critical text-white px-4 py-1.5 rounded hover:opacity-90 transition"
                  >
                    Clear All Data
                  </button>
                  {cleared && (
                    <span className="inline-flex items-center gap-1 text-severity-info text-[11px] ml-3">
                      <Check size={12} /> Dashboard cleared
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function SectionHeader({ title, description }: { title: string; description: string }) {
  return (
    <div className="mb-2">
      <div className="text-sm font-semibold text-text-primary">{title}</div>
      <div className="text-[10px] text-text-secondary">{description}</div>
    </div>
  );
}

function SettingRow({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-border/50 last:border-0">
      <div>
        <div className="text-xs text-text-primary">{label}</div>
        {hint && <div className="text-[9px] text-text-secondary/60">{hint}</div>}
      </div>
      <div className="text-xs text-text-secondary font-mono">{value}</div>
    </div>
  );
}

function NotifRow({ label, desc, enabled }: { label: string; desc: string; enabled: boolean }) {
  return (
    <div className="flex items-center justify-between py-1.5 px-2 rounded bg-bg-main">
      <div>
        <div className="text-[11px] text-text-primary">{label}</div>
        <div className="text-[9px] text-text-secondary">{desc}</div>
      </div>
      <div className={`text-[9px] px-2 py-0.5 rounded-full ${
        enabled
          ? 'bg-severity-critical/10 text-severity-critical'
          : 'bg-border/50 text-text-secondary'
      }`}>
        {enabled ? 'Toast + Center' : 'Center Only'}
      </div>
    </div>
  );
}
