import type { EvidenceRecord } from '../types/trust';

const TYPE_COLOR: Record<string, string> = {
  BEHAVIOR_DEVIATION: 'text-orange-300 border-orange-500/40 bg-orange-500/10',
  BASELINE_DEVIATION: 'text-amber-300 border-amber-500/40 bg-amber-500/10',
  DEVICE_CHANGE: 'text-sky-300 border-sky-500/40 bg-sky-500/10',
  NETWORK_CHANGE: 'text-violet-300 border-violet-500/40 bg-violet-500/10',
  SESSION_ANOMALY: 'text-rose-300 border-rose-500/40 bg-rose-500/10',
  STATE_CHANGE: 'text-fuchsia-300 border-fuchsia-500/40 bg-fuchsia-500/10',
  PRIVILEGE_ESCALATION: 'text-red-300 border-red-500/40 bg-red-500/10',
};

function severityColor(severity: number): string {
  if (severity >= 0.7) return 'bg-rose-500';
  if (severity >= 0.45) return 'bg-orange-400';
  return 'bg-amber-300';
}

/**
 * Explainable evidence. This is the "prove why" part of the product: every
 * record says what was observed, how strongly, and which engine observed it.
 */
export function EvidenceList({
  evidence,
  emptyMessage = 'No evidence recorded — the session matches its trusted baseline.',
}: {
  evidence: EvidenceRecord[];
  emptyMessage?: string;
}) {
  if (evidence.length === 0) {
    return <p className="text-sm text-slate-500">{emptyMessage}</p>;
  }
  const sorted = [...evidence].sort((a, b) => b.severity - a.severity);
  return (
    <ul className="space-y-2">
      {sorted.map((record, index) => (
        <li
          key={`${record.type}-${index}`}
          className="rounded-lg border border-slate-800 bg-slate-900/60 p-3"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
                TYPE_COLOR[record.type] ?? 'border-slate-600 bg-slate-800 text-slate-300'
              }`}
            >
              {record.type}
            </span>
            <span className="flex items-center gap-1.5 text-[11px] text-slate-400">
              <span className="text-slate-600">severity</span>
              <span className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-800">
                <span
                  className={`block h-full ${severityColor(record.severity)}`}
                  style={{ width: `${Math.round(record.severity * 100)}%` }}
                />
              </span>
              <span className="font-mono tabular-nums">{record.severity.toFixed(2)}</span>
            </span>
            <span className="ml-auto font-mono text-[10px] text-slate-600">
              {record.source}
              {record.observed_at
                ? ` · ${new Date(record.observed_at).toLocaleTimeString()}`
                : ''}
            </span>
          </div>
          <p className="mt-1.5 text-xs leading-relaxed text-slate-300">{record.description}</p>
        </li>
      ))}
    </ul>
  );
}
