/* SysLog Threat Analysis — Attack Simulator Page (Phase 5.6 UX) */

import { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../services/api';
import PipelineVisualizer from '../components/monitoring/PipelineVisualizer';
import SimulationSummary from '../components/simulation/SimulationSummary';
import type { SimScenario, SimulationStatus, PipelineStats } from '../types';
import {
  Play, Square, RotateCcw, Zap, Circle, Crosshair,
  ChevronDown, ChevronRight, TriangleAlert,
} from 'lucide-react';

const SPEEDS = ['slow', 'normal', 'fast', 'very_fast'] as const;
const SPEED_LABELS: Record<string, string> = {
  slow: 'Slow', normal: 'Normal', fast: 'Fast', very_fast: 'Very Fast',
};

const PERSIST_KEY = 'syslog-sim-selected';
const PERSIST_SPEED_KEY = 'syslog-sim-speed';
const PERSIST_USER_KEY = 'syslog-sim-user';

export default function Simulator() {
  const [scenarios, setScenarios] = useState<SimScenario[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [speed, setSpeed] = useState<string>(() => localStorage.getItem(PERSIST_SPEED_KEY) || 'normal');
  const [targetUser, setTargetUser] = useState(() => localStorage.getItem(PERSIST_USER_KEY) || 'admin');
  const [status, setStatus] = useState<SimulationStatus | null>(null);
  const [pipeline, setPipeline] = useState<PipelineStats | null>(null);
  const [expandedCat, setExpandedCat] = useState<Set<string>>(new Set());
  const loadedRef = useRef(false);

  const refresh = useCallback(() => {
    api.getSimulationStatus().then(setStatus).catch(() => {});
    api.getPipelineStats().then(setPipeline).catch(() => {});
  }, []);

  useEffect(() => {
    api.getScenarios().then(s => {
      setScenarios(s);
      // Restore persisted selection or default to none (empty state)
      const saved = localStorage.getItem(PERSIST_KEY);
      if (saved && !loadedRef.current) {
        try {
          const ids = JSON.parse(saved) as string[];
          const valid = ids.filter(id => s.some(sc => sc.id === id));
          setSelected(new Set(valid));
        } catch {
          setSelected(new Set()); // Default: nothing selected
        }
      }
      // Default expand all categories
      const cats = [...new Set(s.map(sc => sc.category))];
      setExpandedCat(new Set(cats));
      loadedRef.current = true;
    }).catch(() => {});
    refresh();
    const iv = setInterval(refresh, 2000);
    return () => clearInterval(iv);
  }, [refresh]);

  const toggleScenario = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      localStorage.setItem(PERSIST_KEY, JSON.stringify([...next]));
      return next;
    });
  };

  const selectAll = () => {
    const all = new Set(scenarios.map(s => s.id));
    setSelected(all);
    localStorage.setItem(PERSIST_KEY, JSON.stringify([...all]));
  };

  const selectNone = () => {
    setSelected(new Set());
    localStorage.setItem(PERSIST_KEY, JSON.stringify([]));
  };

  const toggleCategory = (cat: string) => {
    setExpandedCat(prev => {
      const next = new Set(prev);
      next.has(cat) ? next.delete(cat) : next.add(cat);
      return next;
    });
  };

  const handleStart = async () => {
    await api.startSimulation([...selected], speed, targetUser);
    refresh();
  };
  const handleStop = async () => {
    await api.stopSimulation();
    refresh();
  };
  const handleReset = async () => {
    await api.resetSimulation();
    setSelected(new Set());
    localStorage.removeItem(PERSIST_KEY);
    refresh();
  };
  const handleGenerate = async () => {
    if (selected.size === 0) return;
    await api.generateOnce([...selected], targetUser);
    refresh();
  };

  const categories = [...new Set(scenarios.map(s => s.category))];

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Crosshair size={16} className="text-severity-critical" />
            <h1 className="text-base font-semibold text-text-primary">Attack Simulator</h1>
          </div>
          <p className="text-[10px] text-text-secondary mt-0.5">
            Generate realistic attack log sequences to test detection pipelines
          </p>
        </div>
        {status?.active && (
          <div className="flex items-center gap-1.5 text-[10px] text-severity-critical bg-severity-critical/10 px-3 py-1.5 rounded-full border border-severity-critical/30">
            <Circle size={7} className="fill-severity-critical animate-pulse" />
            Running · {status.events_generated} events generated
          </div>
        )}
      </div>

      {/* Pipeline */}
      <PipelineVisualizer stats={pipeline} />

      {/* Simulation Summary */}
      {status && status.events_generated > 0 && (
        <SimulationSummary status={status} pipeline={pipeline} />
      )}

      <div className="grid grid-cols-3 gap-3">
        {/* Scenario Selection */}
        <div className="col-span-2 bg-bg-card border border-border rounded p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="text-xs font-semibold text-text-primary">Attack Scenarios</div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-text-secondary">
                {selected.size} / {scenarios.length} selected
              </span>
              <button
                onClick={selectAll}
                className="text-[10px] text-primary hover:underline"
              >
                All
              </button>
              <span className="text-text-secondary/40">·</span>
              <button
                onClick={selectNone}
                className="text-[10px] text-text-secondary hover:underline"
              >
                None
              </button>
            </div>
          </div>

          {/* Empty state — no scenarios selected */}
          {selected.size === 0 && scenarios.length > 0 && (
            <div className="mb-3 flex items-center gap-2 text-[10px] text-severity-medium bg-severity-medium/10 px-3 py-2 rounded border border-severity-medium/30">
              <TriangleAlert size={12} className="text-severity-medium shrink-0" />
              No scenarios selected. Choose at least one attack type to run simulation.
            </div>
          )}

          {categories.map(cat => (
            <div key={cat} className="mb-2">
              {/* Category header with toggle */}
              <button
                onClick={() => toggleCategory(cat)}
                className="flex items-center gap-1.5 w-full text-[10px] font-semibold text-text-secondary uppercase tracking-wider mb-1.5 hover:text-text-primary transition"
              >
                {expandedCat.has(cat) ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                {cat}
                <span className="ml-1 text-text-secondary/50 normal-case font-normal">
                  ({scenarios.filter(s => s.category === cat && selected.has(s.id)).length}/
                  {scenarios.filter(s => s.category === cat).length})
                </span>
              </button>

              {expandedCat.has(cat) && (
                <div className="grid grid-cols-2 gap-1.5">
                  {scenarios.filter(s => s.category === cat).map(s => (
                    <label
                      key={s.id}
                      className={`flex items-start gap-2 p-2 rounded border cursor-pointer transition text-[11px] ${
                        selected.has(s.id)
                          ? 'border-primary bg-primary/5'
                          : 'border-border hover:border-primary/30'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selected.has(s.id)}
                        onChange={() => toggleScenario(s.id)}
                        className="mt-0.5 accent-primary"
                      />
                      <div>
                        <div className="font-medium text-text-primary">{s.name}</div>
                        <div className="text-[10px] text-text-secondary">{s.description}</div>
                      </div>
                    </label>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Controls Column */}
        <div className="space-y-3">
          {/* Configuration */}
          <div className="bg-bg-card border border-border rounded p-3">
            <div className="text-xs font-semibold text-text-primary mb-2">Configuration</div>
            <div className="space-y-2">
              <div>
                <label className="text-[10px] text-text-secondary block mb-1">Speed</label>
                <div className="grid grid-cols-2 gap-1">
                  {SPEEDS.map(s => (
                    <button
                      key={s}
                      onClick={() => {
                        setSpeed(s);
                        localStorage.setItem(PERSIST_SPEED_KEY, s);
                      }}
                      className={`text-[10px] px-2 py-1 rounded border transition ${
                        speed === s
                          ? 'bg-primary text-white border-primary'
                          : 'border-border text-text-secondary hover:border-primary/30'
                      }`}
                    >
                      {SPEED_LABELS[s]}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="text-[10px] text-text-secondary block mb-1">Target Username</label>
                <input
                  type="text"
                  value={targetUser}
                  onChange={e => {
                    setTargetUser(e.target.value);
                    localStorage.setItem(PERSIST_USER_KEY, e.target.value);
                  }}
                  className="w-full text-xs border border-border rounded px-2 py-1 bg-bg-card text-text-primary"
                  placeholder="admin"
                />
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="bg-bg-card border border-border rounded p-3">
            <div className="text-xs font-semibold text-text-primary mb-2">Controls</div>
            <div className="space-y-1.5">
              {!status?.active ? (
                <button
                  onClick={handleStart}
                  disabled={selected.size === 0}
                  className="w-full flex items-center justify-center gap-1.5 text-[11px] bg-primary text-white px-2 py-2 rounded hover:opacity-90 transition disabled:opacity-40"
                >
                  <Play size={12} /> Start Continuous Simulation
                </button>
              ) : (
                <button
                  onClick={handleStop}
                  className="w-full flex items-center justify-center gap-1.5 text-[11px] bg-severity-critical text-white px-2 py-2 rounded hover:opacity-90 transition"
                >
                  <Square size={12} /> Stop Simulation
                </button>
              )}
              <button
                onClick={handleGenerate}
                disabled={selected.size === 0}
                className="w-full flex items-center justify-center gap-1.5 text-[11px] bg-bg-main text-text-primary border border-border px-2 py-1.5 rounded hover:bg-border transition disabled:opacity-40"
              >
                <Zap size={12} /> Generate Once
              </button>
              <button
                onClick={handleReset}
                className="w-full flex items-center justify-center gap-1.5 text-[11px] text-text-secondary border border-border px-2 py-1.5 rounded hover:bg-bg-main transition"
              >
                <RotateCcw size={12} /> Reset & Clear
              </button>
            </div>
          </div>

          {/* Status */}
          <div className="bg-bg-card border border-border rounded p-3">
            <div className="text-xs font-semibold text-text-primary mb-2">Status</div>
            <div className="space-y-1 text-[10px]">
              <StatusRow
                label="State"
                value={status?.active ? 'Running' : 'Idle'}
                highlight={status?.active}
              />
              <StatusRow label="Speed" value={status?.speed || '-'} />
              <StatusRow label="Events" value={String(status?.events_generated ?? 0)} />
              <StatusRow label="Elapsed" value={status?.elapsed_seconds ? `${status.elapsed_seconds}s` : '-'} />
              <StatusRow label="Scenarios" value={String(selected.size)} />
              <StatusRow label="Target" value={targetUser} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatusRow({ label, value, highlight = false }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className="flex justify-between text-text-secondary">
      <span>{label}</span>
      <span className={`font-mono ${highlight ? 'text-severity-critical' : 'text-text-primary'}`}>
        {value}
      </span>
    </div>
  );
}
