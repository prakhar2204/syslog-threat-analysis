/* SysLog Threat Analysis — Notification Center (Phase 5.6) */

import { useState } from 'react';
import {
  Bell, X, CheckCheck, Trash2, AlertTriangle, ShieldAlert, Info, CheckCircle,
  ChevronDown, ChevronRight, Filter,
} from 'lucide-react';
import { useNotifications, type NotificationType, type NotificationCategory } from '../../context/NotificationContext';

const ICON_MAP: Record<NotificationType, typeof AlertTriangle> = {
  critical: ShieldAlert, warning: AlertTriangle, info: Info, success: CheckCircle,
};
const DOT_COLOR: Record<NotificationType, string> = {
  critical: 'bg-severity-critical', warning: 'bg-severity-high', info: 'bg-primary', success: 'bg-severity-info',
};
const CATEGORY_LABELS: Record<NotificationCategory, string> = {
  system: 'System', detection: 'Detection', monitoring: 'Monitoring',
  evidence: 'Evidence', incidents: 'Incidents',
};

function timeAgo(ts: number): string {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function NotificationCenter() {
  const { center, unreadCount, markRead, markAllRead, clearAll } = useNotifications();
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState<NotificationCategory | 'all'>('all');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const filtered = filter === 'all' ? center : center.filter(n => n.category === filter);

  // Group by category for grouped view
  const grouped = new Map<string, typeof center>();
  for (const n of filtered) {
    const key = `${n.category}::${n.title}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(n);
  }

  const toggleGroup = (key: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  return (
    <div className="relative">
      {/* Bell Button */}
      <button
        onClick={() => setOpen(!open)}
        className="relative p-1.5 rounded hover:bg-bg-main transition"
        title="Notification Center"
      >
        <Bell size={15} className="text-text-secondary" />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 flex items-center justify-center text-[9px] font-bold bg-severity-critical text-white rounded-full px-1 animate-pulse">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* Panel */}
      {open && (
        <>
          {/* Backdrop */}
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />

          {/* Notification Panel */}
          <div className="absolute right-0 top-full mt-1 w-96 max-h-[70vh] bg-bg-card border border-border rounded-lg shadow-xl z-50 flex flex-col notification-panel-enter">
            {/* Panel Header */}
            <div className="flex items-center justify-between px-3 py-2.5 border-b border-border">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-text-primary">Notifications</span>
                {unreadCount > 0 && (
                  <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-severity-critical text-white font-bold">
                    {unreadCount}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={markAllRead}
                  className="p-1 rounded hover:bg-bg-main transition"
                  title="Mark all read"
                >
                  <CheckCheck size={13} className="text-text-secondary" />
                </button>
                <button
                  onClick={clearAll}
                  className="p-1 rounded hover:bg-bg-main transition"
                  title="Clear all"
                >
                  <Trash2 size={13} className="text-text-secondary" />
                </button>
                <button
                  onClick={() => setOpen(false)}
                  className="p-1 rounded hover:bg-bg-main transition"
                >
                  <X size={13} className="text-text-secondary" />
                </button>
              </div>
            </div>

            {/* Category Filter */}
            <div className="flex items-center gap-1 px-3 py-1.5 border-b border-border overflow-x-auto">
              <Filter size={10} className="text-text-secondary shrink-0" />
              {(['all', 'incidents', 'detection', 'evidence', 'monitoring', 'system'] as const).map(cat => (
                <button
                  key={cat}
                  onClick={() => setFilter(cat)}
                  className={`text-[10px] px-2 py-0.5 rounded-full border transition whitespace-nowrap ${
                    filter === cat
                      ? 'bg-primary text-white border-primary'
                      : 'border-border text-text-secondary hover:border-primary/30'
                  }`}
                >
                  {cat === 'all' ? 'All' : CATEGORY_LABELS[cat]}
                </button>
              ))}
            </div>

            {/* Notification List */}
            <div className="flex-1 overflow-y-auto">
              {filtered.length === 0 ? (
                <div className="p-8 text-center">
                  <Bell size={24} className="text-text-secondary/30 mx-auto mb-2" />
                  <div className="text-xs text-text-secondary">No notifications</div>
                  <div className="text-[10px] text-text-secondary/60 mt-1">
                    Alerts and events will appear here
                  </div>
                </div>
              ) : (
                <div>
                  {[...grouped.entries()].map(([key, items]) => {
                    const first = items[0];
                    const totalCount = items.reduce((s, i) => s + i.count, 0);
                    const hasMultiple = totalCount > 1;
                    const isExpanded = expanded.has(key);
                    const Icon = ICON_MAP[first.type];
                    const allRead = items.every(i => i.read);

                    return (
                      <div key={key} className="border-b border-border last:border-0">
                        <button
                          onClick={() => {
                            if (hasMultiple) toggleGroup(key);
                            items.forEach(i => { if (!i.read) markRead(i.id); });
                          }}
                          className={`w-full flex items-start gap-2 px-3 py-2 text-left hover:bg-bg-main/50 transition ${
                            !allRead ? 'bg-primary/5' : ''
                          }`}
                        >
                          <div className="shrink-0 mt-0.5 relative">
                            <Icon size={13} className={`${DOT_COLOR[first.type].replace('bg-', 'text-')}`} />
                            {!allRead && (
                              <span className={`absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full ${DOT_COLOR[first.type]}`} />
                            )}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5">
                              <span className="text-[11px] font-medium text-text-primary truncate">{first.title}</span>
                              {totalCount > 1 && (
                                <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-border text-text-secondary font-mono">
                                  ×{totalCount}
                                </span>
                              )}
                            </div>
                            <div className="text-[10px] text-text-secondary truncate">{first.message}</div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className="text-[9px] text-text-secondary/60">{timeAgo(first.timestamp)}</span>
                              <span className="text-[9px] px-1 py-0 rounded bg-border/50 text-text-secondary/60">
                                {CATEGORY_LABELS[first.category]}
                              </span>
                            </div>
                          </div>
                          {hasMultiple && (
                            <div className="shrink-0 mt-1">
                              {isExpanded ? <ChevronDown size={11} className="text-text-secondary" /> : <ChevronRight size={11} className="text-text-secondary" />}
                            </div>
                          )}
                        </button>
                        {/* Expanded items */}
                        {isExpanded && items.length > 1 && (
                          <div className="pl-8 bg-bg-main/30">
                            {items.map((item, idx) => (
                              <div key={item.id || idx} className="flex items-center gap-2 px-3 py-1.5 border-t border-border/50 text-[10px] text-text-secondary">
                                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${DOT_COLOR[item.type]}`} />
                                <span className="truncate flex-1">{item.message}</span>
                                {item.count > 1 && <span className="font-mono text-[9px]">×{item.count}</span>}
                                <span className="text-[9px] text-text-secondary/50 shrink-0">{timeAgo(item.timestamp)}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
