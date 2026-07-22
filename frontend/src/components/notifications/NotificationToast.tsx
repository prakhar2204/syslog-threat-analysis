/* SysLog Threat Analysis — Notification Toasts (Phase 5.5: count badge) */

import { X, AlertTriangle, ShieldAlert, Info, CheckCircle } from 'lucide-react';
import { useNotifications, type NotificationType } from '../../context/NotificationContext';

const ICON_MAP: Record<NotificationType, typeof AlertTriangle> = {
  critical: ShieldAlert,
  warning: AlertTriangle,
  info: Info,
  success: CheckCircle,
};

const BORDER_MAP: Record<NotificationType, string> = {
  critical: 'border-l-severity-critical',
  warning:  'border-l-severity-high',
  info:     'border-l-primary',
  success:  'border-l-severity-info',
};

const ICON_COLOR: Record<NotificationType, string> = {
  critical: 'text-severity-critical',
  warning:  'text-severity-high',
  info:     'text-primary',
  success:  'text-severity-info',
};

const COUNT_COLOR: Record<NotificationType, string> = {
  critical: 'bg-severity-critical text-white',
  warning:  'bg-severity-high text-white',
  info:     'bg-primary text-white',
  success:  'bg-severity-info text-white',
};

export default function NotificationToast() {
  const { notifications, dismiss } = useNotifications();

  if (notifications.length === 0) return null;

  return (
    <div className="fixed top-14 right-4 z-50 space-y-2 w-80">
      {notifications.map(n => {
        const Icon = ICON_MAP[n.type];
        const message = n.count > 1 ? `${n.count}× ${n.message}` : n.message;
        return (
          <div
            key={n.id}
            className={`${n.exiting ? 'toast-exit' : 'toast-enter'} bg-bg-card border border-border border-l-4 ${BORDER_MAP[n.type]} rounded shadow-lg p-3 flex items-start gap-2`}
          >
            <Icon size={14} className={`${ICON_COLOR[n.type]} shrink-0 mt-0.5`} />
            <div className="flex-1 min-w-0">
              <div className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
                {n.title}
                {n.count > 1 && (
                  <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-bold ${COUNT_COLOR[n.type]}`}>
                    {n.count}
                  </span>
                )}
              </div>
              <div className="text-[10px] text-text-secondary truncate">{message}</div>
            </div>
            <button onClick={() => dismiss(n.id)} className="p-0.5 hover:bg-bg-main rounded transition shrink-0">
              <X size={12} className="text-text-secondary" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
