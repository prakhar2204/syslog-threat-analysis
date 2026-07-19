/* SysLog Threat Analysis — IOC Intelligence Panel */

import { Fingerprint } from 'lucide-react';
import type { Evidence, Incident } from '../../types';

interface Props {
  evidence: Evidence;
  incident: Incident;
}

interface IOCRow {
  type: string;
  value: string;
  occurrences: number;
  relatedRules: string[];
  mitre: string[];
}

export default function IOCPanel({ evidence, incident }: Props) {
  if (evidence.extracted_iocs.length === 0) return null;

  // Aggregate IOCs by value
  const iocMap = new Map<string, IOCRow>();
  for (const ioc of evidence.extracted_iocs) {
    const key = `${ioc.ioc_type}:${ioc.value}`;
    if (iocMap.has(key)) {
      iocMap.get(key)!.occurrences++;
    } else {
      iocMap.set(key, {
        type: ioc.ioc_type,
        value: ioc.value,
        occurrences: 1,
        relatedRules: [...incident.triggered_rules],
        mitre: [...incident.mitre_techniques],
      });
    }
  }

  const rows = Array.from(iocMap.values()).sort((a, b) => b.occurrences - a.occurrences);

  return (
    <div className="bg-bg-card border border-border rounded p-4">
      <div className="text-xs font-semibold text-text-primary flex items-center gap-2 mb-3">
        <Fingerprint size={14} className="text-primary" />
        IOC Intelligence
        <span className="text-[10px] text-text-secondary font-normal ml-auto">
          {rows.length} unique IOCs
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-[11px]">
          <thead>
            <tr className="text-[9px] text-text-secondary uppercase tracking-wider border-b border-border">
              <th className="text-left py-1.5 pr-3">Type</th>
              <th className="text-left py-1.5 pr-3">Value</th>
              <th className="text-center py-1.5 pr-3">Occurrences</th>
              <th className="text-left py-1.5 pr-3">Related Rules</th>
              <th className="text-left py-1.5">MITRE</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rows.slice(0, 25).map((row, i) => (
              <tr key={i} className="hover:bg-bg-main transition-colors">
                <td className="py-1.5 pr-3">
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-primary/10 text-primary font-medium">
                    {row.type}
                  </span>
                </td>
                <td className="py-1.5 pr-3 font-mono text-text-primary">{row.value}</td>
                <td className="py-1.5 pr-3 text-center font-semibold">{row.occurrences}</td>
                <td className="py-1.5 pr-3">
                  <div className="flex flex-wrap gap-0.5">
                    {row.relatedRules.slice(0, 2).map(r => (
                      <span key={r} className="text-[9px] px-1 py-0.5 rounded bg-bg-main text-text-secondary">{r}</span>
                    ))}
                  </div>
                </td>
                <td className="py-1.5">
                  {row.mitre.slice(0, 2).map(t => (
                    <span key={t} className="text-[9px] px-1 py-0.5 rounded bg-primary/10 text-primary font-mono mr-0.5">{t}</span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length > 25 && (
          <div className="text-[10px] text-text-secondary text-center pt-2">+{rows.length - 25} more IOCs</div>
        )}
      </div>
    </div>
  );
}
