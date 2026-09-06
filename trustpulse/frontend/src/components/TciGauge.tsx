import { STATE_COLOR, type TrustState } from '../types/trust';

/**
 * TCI gauge.
 *
 * The label under the number is deliberate: TCI is an index, not a probability,
 * and the UI must not imply otherwise.
 */
export function TciGauge({
  tci,
  state,
  size = 180,
}: {
  tci: number | null;
  state: TrustState;
  size?: number;
}) {
  const value = tci ?? 0;
  const radius = size / 2 - 14;
  const circumference = Math.PI * radius; // half-circle arc
  const progress = Math.max(0, Math.min(100, value)) / 100;
  const color = STATE_COLOR[state] ?? '#38bdf8';

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size / 2 + 26} viewBox={`0 0 ${size} ${size / 2 + 26}`}>
        <path
          d={`M 14 ${size / 2 + 6} A ${radius} ${radius} 0 0 1 ${size - 14} ${size / 2 + 6}`}
          fill="none"
          stroke="#1e293b"
          strokeWidth="12"
          strokeLinecap="round"
        />
        <path
          d={`M 14 ${size / 2 + 6} A ${radius} ${radius} 0 0 1 ${size - 14} ${size / 2 + 6}`}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${circumference * progress} ${circumference}`}
          style={{ transition: 'stroke-dasharray 600ms ease, stroke 300ms ease' }}
        />
        <text
          x={size / 2}
          y={size / 2 - 4}
          textAnchor="middle"
          className="fill-slate-100 font-mono"
          style={{ fontSize: 40, fontWeight: 600 }}
        >
          {tci === null ? '–' : value.toFixed(1)}
        </text>
        <text
          x={size / 2}
          y={size / 2 + 18}
          textAnchor="middle"
          className="fill-slate-500"
          style={{ fontSize: 10, letterSpacing: 1.6 }}
        >
          TRUST CONFIDENCE INDEX
        </text>
      </svg>
      <p className="-mt-1 max-w-[220px] text-center text-[11px] leading-snug text-slate-500">
        Engineering index (0–100), not a probability.
      </p>
    </div>
  );
}
