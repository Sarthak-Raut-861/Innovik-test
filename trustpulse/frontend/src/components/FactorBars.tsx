import { FACTOR_LABEL, type FactorScore } from '../types/trust';

function factorColor(score: number, available: boolean): string {
  if (!available) return '#64748b';
  if (score >= 80) return '#22c55e';
  if (score >= 60) return '#eab308';
  if (score >= 40) return '#f97316';
  return '#ef4444';
}

/**
 * The six TCI factors with their configured and effective weights.
 *
 * Effective weight is shown because unavailable factors are excluded and the
 * remaining weights are renormalised — a blind spot is never scored as distrust.
 */
export function FactorBars({ factors }: { factors: FactorScore[] }) {
  if (factors.length === 0) {
    return <p className="text-sm text-slate-500">No factor data yet.</p>;
  }
  return (
    <div className="space-y-3">
      {factors.map((factor) => {
        const color = factorColor(factor.score, factor.available);
        return (
          <div key={factor.name}>
            <div className="mb-1 flex items-baseline justify-between gap-2">
              <span className="text-xs font-medium text-slate-300">
                {FACTOR_LABEL[factor.name] ?? factor.name}
                {!factor.available ? (
                  <span className="ml-2 rounded bg-slate-800 px-1.5 py-0.5 text-[9px] uppercase text-slate-400">
                    no evidence
                  </span>
                ) : null}
              </span>
              <span className="font-mono text-xs tabular-nums text-slate-300">
                {factor.score.toFixed(0)}
                <span className="text-slate-600">
                  {' '}
                  · w {(factor.effective_weight * 100).toFixed(0)}%
                  {factor.effective_weight !== factor.configured_weight
                    ? ` (cfg ${(factor.configured_weight * 100).toFixed(0)}%)`
                    : ''}
                </span>
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-slate-800">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${Math.max(0, Math.min(100, factor.available ? factor.score : 0))}%`,
                  backgroundColor: color,
                  opacity: factor.available ? 1 : 0.35,
                }}
              />
            </div>
            {factor.reasons.length > 0 ? (
              <div className="mt-1 flex flex-wrap gap-1">
                {factor.reasons.slice(0, 4).map((reason) => (
                  <span
                    key={reason}
                    className="rounded bg-slate-800/80 px-1.5 py-0.5 font-mono text-[9px] text-slate-400"
                  >
                    {reason}
                  </span>
                ))}
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
