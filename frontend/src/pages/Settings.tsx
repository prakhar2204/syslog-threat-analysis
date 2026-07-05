import { useState } from 'react';
import { api } from '../services/api';

export default function SettingsPage() {
  const [cleared, setCleared] = useState(false);

  const handleClear = async () => {
    try {
      await api.clearDashboard();
      setCleared(true);
      setTimeout(() => setCleared(false), 3000);
    } catch { /* silent */ }
  };

  return (
    <div className="space-y-3">
      <div className="text-sm font-semibold text-text-primary">Settings</div>
      <div className="bg-bg-card border border-border rounded p-4 space-y-4 max-w-xl">
        <div>
          <label className="text-xs font-medium text-text-primary block mb-1">Default Log Directory</label>
          <input
            type="text"
            defaultValue="sample_logs/"
            className="text-xs border border-border rounded px-2 py-1.5 bg-white w-full"
            readOnly
          />
          <span className="text-[10px] text-text-secondary">Configured in backend config.py</span>
        </div>

        <div>
          <label className="text-xs font-medium text-text-primary block mb-1">Maximum Log Buffer</label>
          <input
            type="text"
            defaultValue="100,000 entries"
            className="text-xs border border-border rounded px-2 py-1.5 bg-white w-full"
            readOnly
          />
          <span className="text-[10px] text-text-secondary">Older entries are automatically trimmed</span>
        </div>

        <div>
          <label className="text-xs font-medium text-text-primary block mb-1">File Poll Interval</label>
          <input
            type="text"
            defaultValue="200ms"
            className="text-xs border border-border rounded px-2 py-1.5 bg-white w-full"
            readOnly
          />
        </div>

        <hr className="border-border" />

        <div>
          <label className="text-xs font-medium text-text-primary block mb-1">Dashboard Actions</label>
          <button
            onClick={handleClear}
            className="text-xs bg-severity-critical text-white px-3 py-1.5 rounded hover:opacity-90 transition"
          >
            Clear All Data
          </button>
          {cleared && <span className="text-severity-info text-xs ml-2">Dashboard cleared.</span>}
        </div>

        <hr className="border-border" />

        <div>
          <label className="text-xs font-medium text-text-primary block mb-1">About</label>
          <div className="text-xs text-text-secondary space-y-0.5">
            <div>SysLog Threat Analysis v1.0.0</div>
            <div>Real-Time Syslog Monitoring & Threat Detection Dashboard</div>
            <div>Offline SIEM-inspired SOC investigation platform</div>
          </div>
        </div>
      </div>
    </div>
  );
}
