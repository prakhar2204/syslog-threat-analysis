/* SysLog Threat Analysis — Notification Context (Phase 5.6: Notification Center) */

import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';

export type NotificationType = 'critical' | 'warning' | 'info' | 'success';
export type NotificationCategory = 'system' | 'detection' | 'monitoring' | 'evidence' | 'incidents';

export interface Notification {
  id: string;
  type: NotificationType;
  category: NotificationCategory;
  title: string;
  message: string;
  count: number;
  timestamp: number;
  read: boolean;
  exiting?: boolean;
}

interface NotificationContextValue {
  notifications: Notification[];        // visible toasts (critical only)
  center: Notification[];               // all notifications for Notification Center
  unreadCount: number;
  push: (type: NotificationType, title: string, message: string, category?: NotificationCategory, showToast?: boolean) => void;
  dismiss: (id: string) => void;
  markRead: (id: string) => void;
  markAllRead: () => void;
  clearAll: () => void;
}

const NotificationContext = createContext<NotificationContextValue>({
  notifications: [],
  center: [],
  unreadCount: 0,
  push: () => {},
  dismiss: () => {},
  markRead: () => {},
  markAllRead: () => {},
  clearAll: () => {},
});

const MAX_VISIBLE = 4;
const AUTO_DISMISS_MS = 5000;
const MAX_CENTER = 200;
const AGGREGATE_WINDOW_MS = 3000;

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [center, setCenter] = useState<Notification[]>([]);
  const counterRef = useRef(0);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const groupKeyRef = useRef<Map<string, { id: string; timer: ReturnType<typeof setTimeout> }>>(new Map());

  const dismiss = useCallback((id: string) => {
    setNotifications(prev => prev.map(n => n.id === id ? { ...n, exiting: true } : n));
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
      const timer = timersRef.current.get(id);
      if (timer) { clearTimeout(timer); timersRef.current.delete(id); }
    }, 300);
  }, []);

  const push = useCallback((
    type: NotificationType,
    title: string,
    message: string,
    category: NotificationCategory = 'system',
    showToast = false,
  ) => {
    const groupKey = `${type}::${category}::${title}`;

    // Check for aggregation in center
    const existingGroup = groupKeyRef.current.get(groupKey);

    if (existingGroup) {
      // Aggregate: increment count in center
      setCenter(prev => prev.map(n =>
        n.id === existingGroup.id
          ? { ...n, count: n.count + 1, timestamp: Date.now(), read: false }
          : n
      ));
      // Also update toast if visible
      if (showToast) {
        setNotifications(prev => prev.map(n =>
          n.id === existingGroup.id ? { ...n, count: n.count + 1, timestamp: Date.now() } : n
        ));
      }
      // Reset aggregation timer
      clearTimeout(existingGroup.timer);
      const newTimer = setTimeout(() => {
        groupKeyRef.current.delete(groupKey);
      }, AGGREGATE_WINDOW_MS);
      groupKeyRef.current.set(groupKey, { id: existingGroup.id, timer: newTimer });
      return;
    }

    // New notification
    counterRef.current += 1;
    const id = `notif-${counterRef.current}-${Date.now()}`;
    const notif: Notification = {
      id, type, category, title, message, count: 1,
      timestamp: Date.now(), read: false,
    };

    // Always add to center
    setCenter(prev => [notif, ...prev].slice(0, MAX_CENTER));

    // Only show toast for critical items
    if (showToast) {
      setNotifications(prev => {
        const next = [notif, ...prev];
        if (next.length > MAX_VISIBLE) {
          const removed = next.slice(MAX_VISIBLE);
          removed.forEach(n => {
            const t = timersRef.current.get(n.id);
            if (t) { clearTimeout(t); timersRef.current.delete(n.id); }
          });
          return next.slice(0, MAX_VISIBLE);
        }
        return next;
      });

      const timer = setTimeout(() => {
        dismiss(id);
      }, AUTO_DISMISS_MS);
      timersRef.current.set(id, timer);
    }

    // Register for aggregation
    const aggTimer = setTimeout(() => {
      groupKeyRef.current.delete(groupKey);
    }, AGGREGATE_WINDOW_MS);
    groupKeyRef.current.set(groupKey, { id, timer: aggTimer });
  }, [dismiss]);

  const markRead = useCallback((id: string) => {
    setCenter(prev => prev.map(n => n.id === id ? { ...n, read: true } : n));
  }, []);

  const markAllRead = useCallback(() => {
    setCenter(prev => prev.map(n => ({ ...n, read: true })));
  }, []);

  const clearAll = useCallback(() => {
    setCenter([]);
    groupKeyRef.current.clear();
  }, []);

  const unreadCount = center.filter(n => !n.read).length;

  return (
    <NotificationContext.Provider value={{
      notifications, center, unreadCount,
      push, dismiss, markRead, markAllRead, clearAll,
    }}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  return useContext(NotificationContext);
}
