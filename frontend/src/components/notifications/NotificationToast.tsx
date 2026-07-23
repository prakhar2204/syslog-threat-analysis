/* SysLog Threat Analysis — Toast Popups (Phase 5.6: Critical-only) */

import { X, ShieldAlert, AlertTriangle } from 'lucide-react';
import { useNotifications, type NotificationType } from '../../context/NotificationContext';

const ICON_MAP: Record<NotificationType, typeof AlertTriangle> = {
  critical: ShieldAlert,
  warning:  AlertTriangle,
  info:     AlertTriangle,
  success:  AlertTriangle,
};

const STYLE_MAP: Record<NotificationType, { border: string; icon: string; badge: string }> = {
  critical: { border: 'border-l-severity-critical', icon: 'text-severity-critical', badge: 'bg-severity-critical text-white' },
  warning:  { border: 'border-l-severity-high',     icon: 'text-severity-high',     badge: 'bg-severity-high text-white' },
  info:     { border: 'border-l-primary',           icon: 'text-primary',           badge: 'bg-primary text-white' },
  success:  { border: 'border-l-severity-info',     icon: 'text-severity-info',     badge: 'bg-severity-info text-white' },
};

export default function NotificationToast() {
  const { notifications, dismiss } = useNotifications();

  if (notifications.length === 0) return null;

  return (
    <div className="fixed top-14 right-4 z-50 space-y-2 w-80 pointer-events-none">
      {notifications.map(n => {
        const Icon = ICON_MAP[n.type];
        const style = STYLE_MAP[n.type];
        return (
          <div
            key={n.id}
            className={`pointer-events-auto ${n.exiting ? 'toast-exit' : 'toast-enter'} bg-bg-card border border-border border-l-4 ${style.border} rounded shadow-lg p-3 flex items-start gap-2`}
          >
            <Icon size={14} className={`${style.icon} shrink-0 mt-0.5`} />
            <div className="flex-1 min-w-0">
              <div className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
                {n.title}
                {n.count > 1 && (
                  <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-bold ${style.badge}`}>
                    ×{n.count}
                  </span>
                )}
              </div>
              <div className="text-[10px] text-text-secondary truncate">{n.message}</div>
            </div>
            <button
              onClick={() => dismiss(n.id)}
              className="p-0.5 hover:bg-bg-main rounded transition shrink-0"
            >
              <X size={12} className="text-text-secondary" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
