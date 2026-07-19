/* SysLog Threat Analysis - Attack Simulator Page */

import { useEffect, useState, useCallback } from 'react';
import { api } from '../services/api';
import PipelineVisualizer from '../components/monitoring/PipelineVisualizer';
import SimulationSummary from '../components/simulation/SimulationSummary';
import type { SimScenario, SimulationStatus, PipelineStats } from '../types';
import { Play, Square, RotateCcw, Zap, Circle } from 'lucide-react';

const SPEEDS = ['slow', 'normal', 'fast', 'very_fast'] as const;
const SPEED_LABELS: Record<string, string> = { slow: 'Slow', normal: 'Normal', fast: 'Fast', very_fast: 'Very Fast' };

export default function Simulator() {
  const [scenarios, setScenarios] = useState<SimScenario[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [speed, setSpeed] = useState<string>('normal');
  const [targetUser, setTargetUser] = useState('admin');
  const [status, setStatus] = useState<SimulationStatus | null>(null);
  const [pipeline, setPipeline] = useState<PipelineStats | null>(null);

  const refresh = useCallback(() => {
    api.getSimulationStatus().then(setStatus).catch(() => {});
    api.getPipelineStats().then(setPipeline).catch(() => {});
  }, []);

  useEffect(() => {
    api.getScenarios().then((s) => {
      setScenarios(s);
      setSelected(new Set(s.map(sc => sc.id)));
    }).catch(() => {});
    refresh();
    const iv = setInterval(refresh, 2000);
    return () => clearInterval(iv);
  }, [refresh]);

  const toggleScenario = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
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
    refresh();
  };
  const handleGenerate = async () => {
    await api.generateOnce([...selected], targetUser);
    refresh();
  };

  const categories = [...new Set(scenarios.map(s => s.category))];

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-base font-semibold text-text-primary">Attack Simulator</h1>
        {status?.active && (
          <div className="flex items-center gap-1.5 text-[10px] text-severity-critical">
            <Circle size={6} className="fill-severity-critical animate-pulse" />
            Simulation Running - {status.events_generated} events
          </div>
        )}
      </div>

      {/* Pipeline */}
      <PipelineVisualizer stats={pipeline} />

      {/* Simulation Summary — shown after completion */}
      {status && <SimulationSummary status={status} pipeline={pipeline} />}

      <div className="grid grid-cols-3 gap-3">
        {/* Scenario Selection */}
        <div className="col-span-2 bg-bg-card border border-border rounded p-3">
          <div className="text-xs font-semibold text-text-primary mb-3">Attack Scenarios</div>
          {categories.map(cat => (
            <div key={cat} className="mb-3">
              <div className="text-[10px] font-semibold text-text-secondary uppercase tracking-wider mb-1.5">
                {cat}
              </div>
              <div className="grid grid-cols-2 gap-1.5">
                {scenarios.filter(s => s.category === cat).map(s => (
                  <label
                    key={s.id}
                    className={`flex items-start gap-2 p-2 rounded border cursor-pointer transition text-[11px] ${
                      selected.has(s.id) ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/30'
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
            </div>
          ))}
        </div>

        {/* Controls */}
        <div className="space-y-3">
          {/* Configuration */}
          <div className="bg-bg-card border border-border rounded p-3">
            <div className="text-xs font-semibold text-text-primary mb-2">Configuration</div>
            <div className="space-y-2">
              <div>
                <label className="text-[10px] text-text-secondary block mb-0.5">Speed</label>
                <div className="flex gap-1">
                  {SPEEDS.map(s => (
                    <button
                      key={s}
                      onClick={() => setSpeed(s)}
                      className={`text-[10px] px-2 py-1 rounded border transition ${
                        speed === s ? 'bg-primary text-white border-primary' : 'border-border text-text-secondary hover:border-primary/30'
                      }`}
                    >
                      {SPEED_LABELS[s]}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="text-[10px] text-text-secondary block mb-0.5">Target Username</label>
                <input
                  type="text"
                  value={targetUser}
                  onChange={e => setTargetUser(e.target.value)}
                  className="w-full text-xs border border-border rounded px-2 py-1 bg-bg-card text-text-primary"
                />
              </div>
              <div className="text-[10px] text-text-secondary">
                Selected: {selected.size} / {scenarios.length} scenarios
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="bg-bg-card border border-border rounded p-3">
            <div className="text-xs font-semibold text-text-primary mb-2">Controls</div>
            <div className="grid grid-cols-2 gap-1.5">
              {!status?.active ? (
                <button onClick={handleStart} disabled={selected.size === 0}
                  className="flex items-center justify-center gap-1 text-[11px] bg-primary text-white px-2 py-1.5 rounded hover:opacity-90 transition disabled:opacity-40">
                  <Play size={11} /> Start
                </button>
              ) : (
                <button onClick={handleStop}
                  className="flex items-center justify-center gap-1 text-[11px] bg-severity-critical text-white px-2 py-1.5 rounded hover:opacity-90 transition">
                  <Square size={11} /> Stop
                </button>
              )}
              <button onClick={handleGenerate} disabled={selected.size === 0}
                className="flex items-center justify-center gap-1 text-[11px] bg-bg-main text-text-primary border border-border px-2 py-1.5 rounded hover:bg-border transition disabled:opacity-40">
                <Zap size={11} /> Generate
              </button>
              <button onClick={handleReset}
                className="col-span-2 flex items-center justify-center gap-1 text-[11px] text-text-secondary border border-border px-2 py-1.5 rounded hover:bg-bg-main transition">
                <RotateCcw size={11} /> Reset
              </button>
            </div>
          </div>

          {/* Status */}
          <div className="bg-bg-card border border-border rounded p-3">
            <div className="text-xs font-semibold text-text-primary mb-2">Simulation Status</div>
            <div className="space-y-1 text-[10px]">
              <Row label="Status" value={status?.active ? 'Running' : 'Idle'} />
              <Row label="Speed" value={status?.speed || '-'} />
              <Row label="Events" value={String(status?.events_generated ?? 0)} />
              <Row label="Elapsed" value={status?.elapsed_seconds ? `${status.elapsed_seconds}s` : '-'} />
              <Row label="Scenarios" value={String(status?.scenarios?.length ?? 0)} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between text-text-secondary">
      <span>{label}</span>
      <span className="text-text-primary font-mono">{value}</span>
    </div>
  );
}
