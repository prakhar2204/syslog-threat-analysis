/* SysLog Threat Analysis — Notification Context */

import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';

export type NotificationType = 'critical' | 'warning' | 'info' | 'success';

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  timestamp: number;
  exiting?: boolean;
}

interface NotificationContextValue {
  notifications: Notification[];
  push: (type: NotificationType, title: string, message: string) => void;
  dismiss: (id: string) => void;
}

const NotificationContext = createContext<NotificationContextValue>({
  notifications: [],
  push: () => {},
  dismiss: () => {},
});

const MAX_VISIBLE = 5;
const AUTO_DISMISS_MS = 5000;

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const counterRef = useRef(0);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: string) => {
    // Start exit animation
    setNotifications(prev => prev.map(n => n.id === id ? { ...n, exiting: true } : n));
    // Remove after animation
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
      const timer = timersRef.current.get(id);
      if (timer) { clearTimeout(timer); timersRef.current.delete(id); }
    }, 300);
  }, []);

  const push = useCallback((type: NotificationType, title: string, message: string) => {
    counterRef.current += 1;
    const id = `notif-${counterRef.current}-${Date.now()}`;
    const notif: Notification = { id, type, title, message, timestamp: Date.now() };

    setNotifications(prev => {
      const next = [notif, ...prev];
      // Remove oldest if over limit
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

    // Auto-dismiss
    const timer = setTimeout(() => dismiss(id), AUTO_DISMISS_MS);
    timersRef.current.set(id, timer);
  }, [dismiss]);

  return (
    <NotificationContext.Provider value={{ notifications, push, dismiss }}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  return useContext(NotificationContext);
}
