/* SysLog Threat Analysis — Notification Context (Phase 5.5: Aggregated) */

import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';

export type NotificationType = 'critical' | 'warning' | 'info' | 'success';

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  count: number;        // aggregated count
  timestamp: number;
  exiting?: boolean;
}

interface NotificationContextValue {
  notifications: Notification[];
  history: Notification[];
  push: (type: NotificationType, title: string, message: string, aggregate?: boolean) => void;
  dismiss: (id: string) => void;
  clearHistory: () => void;
}

const NotificationContext = createContext<NotificationContextValue>({
  notifications: [],
  history: [],
  push: () => {},
  dismiss: () => {},
  clearHistory: () => {},
});

const MAX_VISIBLE = 6;
const AUTO_DISMISS_MS = 6000;
// Aggregation window: same-type events within this window merge into one toast
const AGGREGATE_WINDOW_MS = 2000;

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [history, setHistory] = useState<Notification[]>([]);
  const counterRef = useRef(0);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  // Map from groupKey -> notification id (for aggregation)
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
    aggregate = false,
  ) => {
    const groupKey = aggregate ? `${type}::${title}` : null;

    // --- Aggregation: merge into existing visible toast of same type+title ---
    if (groupKey && groupKeyRef.current.has(groupKey)) {
      const { id, timer } = groupKeyRef.current.get(groupKey)!;
      // Increment count on existing toast
      setNotifications(prev => prev.map(n =>
        n.id === id ? { ...n, count: n.count + 1, timestamp: Date.now() } : n
      ));
      // Reset the auto-dismiss timer
      clearTimeout(timer);
      const newTimer = setTimeout(() => {
        dismiss(id);
        groupKeyRef.current.delete(groupKey);
      }, AUTO_DISMISS_MS);
      groupKeyRef.current.set(groupKey, { id, timer: newTimer });
      return;
    }

    // --- New notification ---
    counterRef.current += 1;
    const id = `notif-${counterRef.current}-${Date.now()}`;
    const notif: Notification = { id, type, title, message, count: 1, timestamp: Date.now() };

    setNotifications(prev => {
      const next = [notif, ...prev];
      if (next.length > MAX_VISIBLE) {
        const removed = next.slice(MAX_VISIBLE);
        removed.forEach(n => {
          const t = timersRef.current.get(n.id);
          if (t) { clearTimeout(t); timersRef.current.delete(n.id); }
          // Remove from group key tracking if present
          for (const [key, val] of groupKeyRef.current.entries()) {
            if (val.id === n.id) { groupKeyRef.current.delete(key); }
          }
        });
        return next.slice(0, MAX_VISIBLE);
      }
      return next;
    });

    // Add to persistent history
    setHistory(prev => [notif, ...prev].slice(0, 100));

    const timer = setTimeout(() => {
      dismiss(id);
      if (groupKey) groupKeyRef.current.delete(groupKey);
    }, AUTO_DISMISS_MS);
    timersRef.current.set(id, timer);

    // Register for aggregation
    if (groupKey) {
      groupKeyRef.current.set(groupKey, { id, timer });
    }
  }, [dismiss]);

  const clearHistory = useCallback(() => setHistory([]), []);

  return (
    <NotificationContext.Provider value={{ notifications, history, push, dismiss, clearHistory }}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  return useContext(NotificationContext);
}
