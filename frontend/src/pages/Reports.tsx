import { useState } from 'react';
import { api } from '../services/api';
import { FileJson, FileSpreadsheet, FileText, Check } from 'lucide-react';

export default function Reports() {
  const [exported, setExported] = useState<string | null>(null);

  const doExport = (format: 'json' | 'csv' | 'pdf') => {
    api.exportReport(format);
    setExported(format);
    setTimeout(() => setExported(null), 3000);
  };

  return (
    <div className="space-y-3">
      <div className="text-sm font-semibold text-text-primary">Export Reports</div>
      <div className="bg-bg-card border border-border rounded p-4">
        <p className="text-xs text-text-secondary mb-4">
          Export current dashboard data, incidents, alerts, and parsed logs. All exported data originates from
          actual processed syslog events.
        </p>
        <div className="grid grid-cols-3 gap-3">
          <button
            onClick={() => doExport('json')}
            className="border border-border rounded p-4 hover:bg-bg-main transition-colors text-center"
          >
            <FileJson size={24} className="mx-auto text-primary mb-2" />
            <div className="text-xs font-medium">JSON Report</div>
            <div className="text-[10px] text-text-secondary mt-1">Full structured report with incidents, alerts, and statistics</div>
            {exported === 'json' && <div className="text-severity-info text-[10px] mt-2 flex items-center justify-center gap-1"><Check size={12} /> Exported</div>}
          </button>

          <button
            onClick={() => doExport('csv')}
            className="border border-border rounded p-4 hover:bg-bg-main transition-colors text-center"
          >
            <FileSpreadsheet size={24} className="mx-auto text-severity-info mb-2" />
            <div className="text-xs font-medium">CSV Export</div>
            <div className="text-[10px] text-text-secondary mt-1">All parsed log entries in tabular format</div>
            {exported === 'csv' && <div className="text-severity-info text-[10px] mt-2 flex items-center justify-center gap-1"><Check size={12} /> Exported</div>}
          </button>

          <button
            onClick={() => doExport('pdf')}
            className="border border-border rounded p-4 hover:bg-bg-main transition-colors text-center"
          >
            <FileText size={24} className="mx-auto text-severity-critical mb-2" />
            <div className="text-xs font-medium">PDF Report</div>
            <div className="text-[10px] text-text-secondary mt-1">Incident summary with timeline, analysis, and recommendations</div>
            {exported === 'pdf' && <div className="text-severity-info text-[10px] mt-2 flex items-center justify-center gap-1"><Check size={12} /> Exported</div>}
          </button>
        </div>
      </div>
    </div>
  );
}
