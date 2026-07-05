import type { DashboardStats } from '../../types';
import { Activity, AlertTriangle, ShieldAlert, ShieldCheck, FileText } from 'lucide-react';

interface Props {
  stats: DashboardStats | null;
}

const CARDS = [
  { key: 'total_logs' as const, label: 'Total Logs', icon: FileText, color: 'text-primary' },
  { key: 'info_events' as const, label: 'Info', icon: ShieldCheck, color: 'text-severity-info' },
  { key: 'warning_events' as const, label: 'Warnings', icon: Activity, color: 'text-severity-medium' },
  { key: 'high_events' as const, label: 'High', icon: AlertTriangle, color: 'text-severity-high' },
  { key: 'critical_events' as const, label: 'Critical', icon: ShieldAlert, color: 'text-severity-critical' },
];

export default function StatsCards({ stats }: Props) {
  return (
    <div className="grid grid-cols-5 gap-3">
      {CARDS.map(({ key, label, icon: Icon, color }) => (
        <div key={key} className="bg-bg-card border border-border rounded px-4 py-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-text-secondary">{label}</span>
            <Icon size={14} className={color} />
          </div>
          <div className="text-2xl font-semibold mt-1">
            {stats ? stats[key].toLocaleString() : '—'}
          </div>
        </div>
      ))}
    </div>
  );
}
