import type { Confidence, Trend, TrustState } from '../types/trust';
import { STATE_COLOR } from '../types/trust';

const STATE_COPY: Record<TrustState, string> = {
  TRUSTED: 'Session behaves consistently with its trusted baseline.',
  DEGRADED: 'Trust is reduced; evidence is accumulating but is not decisive.',
  SUSPICIOUS: 'Multiple independent signals disagree with the baseline.',
  CRITICAL: 'Trust has collapsed; sensitive actions should not proceed.',
  BLOCKED: 'Session is blocked pending operator or application action.',
  CONTAINED: 'Containment is active; the session is isolated.',
};

export function StateBadge({
  state,
  size = 'md',
}: {
  state: TrustState;
  size?: 'sm' | 'md';
}) {
  const color = STATE_COLOR[state] ?? '#94a3b8';
  const padding = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-semibold uppercase tracking-wider ${padding}`}
      style={{ color, backgroundColor: `${color}1f`, border: `1px solid ${color}55` }}
      title={STATE_COPY[state]}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }}
      />
      {state}
    </span>
  );
}

export function TrendIndicator({ trend }: { trend: Trend }) {
  const glyph =
    trend === 'FALLING' ? '▼' : trend === 'RISING' ? '▲' : trend === 'STABLE' ? '■' : '–';
  const color =
    trend === 'FALLING'
      ? 'text-rose-400'
      : trend === 'RISING'
        ? 'text-emerald-400'
        : 'text-slate-500';
  return (
    <span className={`font-mono text-xs ${color}`} title={`TCI trend: ${trend}`}>
      {glyph} {trend}
    </span>
  );
}

export function ConfidencePill({ confidence }: { confidence: Confidence }) {
  const color =
    confidence === 'HIGH'
      ? 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10'
      : confidence === 'MEDIUM'
        ? 'text-amber-300 border-amber-500/40 bg-amber-500/10'
        : 'text-slate-300 border-slate-600 bg-slate-700/30';
  return (
    <span
      className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${color}`}
      title="How much evidence supports the score — separate from the score itself."
    >
      evidence: {confidence}
    </span>
  );
}

export function RiskBadge({ risk }: { risk?: number | null }) {
  if (risk === null || risk === undefined) return <span className="text-slate-600">–</span>;
  const color =
    risk >= 85 ? 'text-rose-400' : risk >= 60 ? 'text-orange-400' : risk >= 30 ? 'text-amber-300' : 'text-emerald-400';
  return <span className={`font-mono text-sm ${color}`}>{risk}</span>;
}

export function DecisionBadge({ decision }: { decision?: string | null }) {
  if (!decision) return <span className="text-slate-600">–</span>;
  const styles: Record<string, string> = {
    ALLOW: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
    STEP_UP: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
    BLOCK: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
    REVOKE: 'bg-rose-600/20 text-rose-200 border-rose-500/50',
    CONTAIN: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/40',
    // Neutral style for a value this build does not recognise. Not an API state.
    UNKNOWN: 'bg-slate-600/20 text-slate-300 border-slate-500/40',
  };
  return (
    <span
      className={`rounded border px-2 py-0.5 font-mono text-[11px] uppercase ${
        styles[decision] ?? styles.UNKNOWN
      }`}
    >
      {decision}
    </span>
  );
}
