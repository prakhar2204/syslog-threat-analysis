import { useEffect, useState } from 'react';
import { Shield } from 'lucide-react';
import { useApp } from '../../context/AppContext';

export default function Header() {
  const { state } = useApp();
  const [clock, setClock] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

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
        <span className={`inline-block w-2 h-2 rounded-full ${state.wsConnected ? 'bg-severity-info' : 'bg-severity-critical'}`} />
        <span className="text-text-secondary">
          {state.wsConnected ? 'Connected' : 'Disconnected'}
        </span>
      </div>
    </header>
  );
}
