/* SysLog Threat Analysis — Header (Phase 5.6) */

import { useEffect, useState } from 'react';
import { Shield, Sun, Moon, Monitor } from 'lucide-react';
import { useApp } from '../../context/AppContext';
import { useTheme } from '../../context/ThemeContext';
import NotificationCenter from '../notifications/NotificationCenter';

export default function Header() {
  const { state } = useApp();
  const { mode, setMode } = useTheme();
  const [clock, setClock] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const cycleTheme = () => {
    const next: Record<string, 'light' | 'dark' | 'system'> = {
      light: 'dark',
      dark: 'system',
      system: 'light',
    };
    setMode(next[mode]);
  };

  const ThemeIcon = mode === 'dark' ? Moon : mode === 'system' ? Monitor : Sun;

  return (
    <header className="h-12 bg-bg-card border-b border-border flex items-center justify-between px-4 shrink-0">
      <div className="flex items-center gap-2">
        <Shield size={18} className="text-primary" />
        <span className="font-semibold text-sm text-text-primary">SysLog Threat Analysis</span>
      </div>

      <div className="text-xs text-text-secondary font-mono">
        {clock.toLocaleDateString('en-US', { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' })}
        {' '}
        {clock.toLocaleTimeString('en-US', { hour12: false })}
      </div>

      <div className="flex items-center gap-2 text-xs">
        {/* Notification Center */}
        <NotificationCenter />

        {/* Theme Toggle */}
        <button
          onClick={cycleTheme}
          className="p-1.5 rounded hover:bg-bg-main transition"
          title={`Theme: ${mode}`}
        >
          <ThemeIcon size={14} className="text-text-secondary" />
        </button>

        {/* Connection Status */}
        <div className="flex items-center gap-1.5 pl-2 border-l border-border">
          <span className={`inline-block w-2 h-2 rounded-full ${state.wsConnected ? 'bg-severity-info' : 'bg-severity-critical'}`} />
          <span className="text-text-secondary text-[11px]">
            {state.wsConnected ? 'Live' : 'Offline'}
          </span>
        </div>
      </div>
    </header>
  );
}
