/* SysLog Threat Analysis — Global Application State */

import { createContext, useContext, useCallback, useEffect, useReducer, useRef, type ReactNode } from 'react';
import type { Alert, DashboardStats, Incident, LogEntry, WSMessage } from '../types';
import { useWebSocket } from '../hooks/useWebSocket';

interface AppState {
  logs: LogEntry[];
  alerts: Alert[];
  incidents: Incident[];
  stats: DashboardStats | null;
  wsConnected: boolean;
}

type Action =
  | { type: 'ADD_LOGS'; payload: LogEntry[] }
  | { type: 'ADD_ALERT'; payload: Alert }
  | { type: 'ADD_INCIDENT'; payload: Incident }
  | { type: 'SET_STATS'; payload: DashboardStats }
  | { type: 'SET_WS'; payload: boolean }
  | { type: 'CLEAR' };

const MAX_LOGS = 500;

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'ADD_LOGS': {
      const merged = [...action.payload, ...state.logs].slice(0, MAX_LOGS);
      return { ...state, logs: merged };
    }
    case 'ADD_ALERT':
      return { ...state, alerts: [action.payload, ...state.alerts].slice(0, 200) };
    case 'ADD_INCIDENT': {
      const existing = state.incidents.findIndex(i => i.incident_id === action.payload.incident_id);
      let incidents: Incident[];
      if (existing >= 0) {
        incidents = [...state.incidents];
        incidents[existing] = action.payload;
      } else {
        incidents = [action.payload, ...state.incidents];
      }
      return { ...state, incidents };
    }
    case 'SET_STATS':
      return { ...state, stats: action.payload };
    case 'SET_WS':
      return { ...state, wsConnected: action.payload };
    case 'CLEAR':
      return { ...state, logs: [], alerts: [], incidents: [], stats: null };
    default:
      return state;
  }
}

const initial: AppState = {
  logs: [],
  alerts: [],
  incidents: [],
  stats: null,
  wsConnected: false,
};

const AppContext = createContext<{
  state: AppState;
  dispatch: React.Dispatch<Action>;
}>({ state: initial, dispatch: () => {} });

export function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initial);

  const handleWS = useCallback((msg: WSMessage) => {
    switch (msg.type) {
      case 'new_logs':
        dispatch({ type: 'ADD_LOGS', payload: msg.data as LogEntry[] });
        break;
      case 'new_alert':
        dispatch({ type: 'ADD_ALERT', payload: msg.data as Alert });
        break;
      case 'new_incident':
        dispatch({ type: 'ADD_INCIDENT', payload: msg.data as Incident });
        break;
      case 'stats_update':
        dispatch({ type: 'SET_STATS', payload: msg.data as DashboardStats });
        break;
    }
  }, []);

  const { connected } = useWebSocket(handleWS);

  // Track previous connection state to avoid dispatching during render
  const prevConnected = useRef(connected);
  useEffect(() => {
    if (prevConnected.current !== connected) {
      prevConnected.current = connected;
      dispatch({ type: 'SET_WS', payload: connected });
    }
  }, [connected]);

  return (
    <AppContext.Provider value={{ state, dispatch }}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  return useContext(AppContext);
}
