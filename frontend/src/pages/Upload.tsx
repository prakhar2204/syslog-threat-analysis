/* SysLog Threat Analysis — Upload Investigation Page (Phase 5.6) */

import { useCallback, useState, useRef, useEffect } from 'react';
import { Upload, FileText, CheckCircle, AlertTriangle, Loader2, Clock, X, Plus } from 'lucide-react';
import { api } from '../services/api';
import type { UploadSession } from '../types';

type UploadState = 'idle' | 'uploading' | 'success' | 'error';

export default function UploadPage() {
  const [files, setFiles] = useState<File[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [uploadState, setUploadState] = useState<UploadState>('idle');
  const [result, setResult] = useState<UploadSession | null>(null);
  const [multiResult, setMultiResult] = useState<UploadSession[] | null>(null);
  const [error, setError] = useState<string>('');
  const [history, setHistory] = useState<UploadSession[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.getUploadHistory().then(setHistory).catch(() => {});
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const dropped = Array.from(e.dataTransfer.files).filter(f =>
      f.name.endsWith('.log') || f.name.endsWith('.txt') || f.name.endsWith('.syslog') || f.size < 50_000_000
    );
    if (dropped.length > 0) {
      setFiles(prev => [...prev, ...dropped]);
    }
  }, []);

  const handleSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setFiles(prev => [...prev, ...Array.from(e.target.files!)]);
    }
  }, []);

  const removeFile = (idx: number) => {
    setFiles(prev => prev.filter((_, i) => i !== idx));
  };

  const handleUpload = async () => {
    if (files.length === 0) return;

    setUploadState('uploading');
    setError('');
    setResult(null);
    setMultiResult(null);

    try {
      if (files.length === 1) {
        const res = await api.uploadFile(files[0]);
        setResult(res);
      } else {
        const res = await api.uploadMultiple(files);
        setMultiResult(res.sessions);
      }
      setUploadState('success');
      setFiles([]);
      // Refresh history
      api.getUploadHistory().then(setHistory).catch(() => {});
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Upload failed');
      setUploadState('error');
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  };

  return (
    <div className="space-y-4 max-w-4xl">
      {/* Page Header */}
      <div>
        <h1 className="text-base font-semibold text-text-primary">Upload Log File</h1>
        <p className="text-[11px] text-text-secondary mt-0.5">
          Upload syslog files for investigation. Files are processed through the full detection pipeline.
        </p>
      </div>

      {/* Drop Zone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all ${
          dragOver
            ? 'border-primary bg-primary/5 scale-[1.01]'
            : 'border-border hover:border-primary/40 hover:bg-bg-card'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          multiple
          accept=".log,.txt,.syslog"
          onChange={handleSelect}
          className="hidden"
        />
        <Upload size={28} className={`mx-auto mb-3 ${dragOver ? 'text-primary' : 'text-text-secondary/40'}`} />
        <div className="text-sm font-medium text-text-primary mb-1">
          Drop log files here or click to browse
        </div>
        <div className="text-[10px] text-text-secondary">
          Supported: .log, .txt, .syslog · Max 50MB per file
        </div>
      </div>

      {/* Selected Files */}
      {files.length > 0 && (
        <div className="bg-bg-card border border-border rounded-lg p-3">
          <div className="text-xs font-semibold text-text-primary mb-2">
            Selected Files ({files.length})
          </div>
          <div className="space-y-1.5">
            {files.map((f, i) => (
              <div key={`${f.name}-${i}`} className="flex items-center gap-2 text-[11px] bg-bg-main rounded px-2.5 py-1.5">
                <FileText size={12} className="text-primary shrink-0" />
                <span className="flex-1 text-text-primary truncate">{f.name}</span>
                <span className="text-text-secondary">{formatBytes(f.size)}</span>
                <button onClick={() => removeFile(i)} className="p-0.5 hover:bg-border rounded transition">
                  <X size={11} className="text-text-secondary" />
                </button>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-2 mt-3">
            <button
              onClick={handleUpload}
              disabled={uploadState === 'uploading'}
              className="flex items-center gap-1.5 text-[11px] bg-primary text-white px-4 py-1.5 rounded hover:opacity-90 transition disabled:opacity-50"
            >
              {uploadState === 'uploading' ? (
                <><Loader2 size={12} className="animate-spin" /> Processing...</>
              ) : (
                <><Upload size={12} /> Analyze {files.length} {files.length === 1 ? 'File' : 'Files'}</>
              )}
            </button>
            <button
              onClick={() => inputRef.current?.click()}
              className="flex items-center gap-1 text-[11px] text-text-secondary border border-border px-3 py-1.5 rounded hover:bg-bg-main transition"
            >
              <Plus size={11} /> Add More
            </button>
          </div>
        </div>
      )}

      {/* Error */}
      {uploadState === 'error' && error && (
        <div className="bg-severity-critical/10 border border-severity-critical/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle size={14} className="text-severity-critical shrink-0 mt-0.5" />
          <div>
            <div className="text-xs font-medium text-severity-critical">Upload Failed</div>
            <div className="text-[10px] text-text-secondary mt-0.5">{error}</div>
          </div>
        </div>
      )}

      {/* Single file result */}
      {uploadState === 'success' && result && (
        <div className="bg-severity-info/10 border border-severity-info/30 rounded-lg p-4 result-slide-in">
          <div className="flex items-center gap-2 mb-3">
            <CheckCircle size={16} className="text-severity-info" />
            <span className="text-sm font-semibold text-text-primary">Analysis Complete</span>
          </div>
          <ResultGrid session={result} />
        </div>
      )}

      {/* Multi file result */}
      {uploadState === 'success' && multiResult && (
        <div className="bg-severity-info/10 border border-severity-info/30 rounded-lg p-4 result-slide-in">
          <div className="flex items-center gap-2 mb-3">
            <CheckCircle size={16} className="text-severity-info" />
            <span className="text-sm font-semibold text-text-primary">{multiResult.length} Files Analyzed</span>
          </div>
          <div className="space-y-3">
            {multiResult.map(s => (
              <div key={s.session_id} className="bg-bg-card rounded p-3 border border-border">
                <div className="text-[11px] font-medium text-text-primary mb-1.5">{s.filename}</div>
                <ResultGrid session={s} compact />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Upload History */}
      {history.length > 0 && (
        <div className="bg-bg-card border border-border rounded-lg p-3">
          <div className="text-xs font-semibold text-text-primary mb-2">Upload History</div>
          <div className="space-y-1">
            {history.map(s => (
              <div key={s.session_id} className="flex items-center gap-3 text-[10px] py-1.5 px-2 rounded hover:bg-bg-main transition">
                <FileText size={11} className="text-text-secondary shrink-0" />
                <span className="flex-1 text-text-primary truncate">{s.filename}</span>
                <span className="text-text-secondary">{s.lines} lines</span>
                <span className="text-text-secondary">{s.events} events</span>
                <span className="text-text-secondary">{s.alerts} alerts</span>
                <span className="text-text-secondary">{s.incidents} incidents</span>
                <span className="flex items-center gap-0.5 text-text-secondary">
                  <Clock size={9} />{s.duration_seconds}s
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ResultGrid({ session, compact = false }: { session: UploadSession; compact?: boolean }) {
  const metrics = [
    { label: 'Lines Parsed', value: session.lines, color: 'text-text-primary' },
    { label: 'Events', value: session.events, color: 'text-primary' },
    { label: 'Alerts', value: session.alerts, color: session.alerts > 0 ? 'text-severity-high' : 'text-text-secondary' },
    { label: 'Incidents', value: session.incidents, color: session.incidents > 0 ? 'text-severity-critical' : 'text-text-secondary' },
    { label: 'Duration', value: `${session.duration_seconds}s`, color: 'text-text-secondary' },
  ];

  return (
    <div className={`grid ${compact ? 'grid-cols-5 gap-2' : 'grid-cols-5 gap-3'}`}>
      {metrics.map(m => (
        <div key={m.label} className="text-center">
          <div className={`${compact ? 'text-sm' : 'text-lg'} font-bold ${m.color} font-mono`}>
            {m.value}
          </div>
          <div className="text-[9px] text-text-secondary">{m.label}</div>
        </div>
      ))}
    </div>
  );
}
