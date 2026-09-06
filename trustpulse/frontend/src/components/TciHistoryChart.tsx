import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import type { TrustHistoryPoint } from '../types/trust';

/**
 * TCI history with the configured state bands drawn as reference lines, so an
 * analyst can see exactly which boundary was crossed and when.
 */
export function TciHistoryChart({
  points,
  height = 240,
  bands = [85, 70, 50, 30],
}: {
  points: TrustHistoryPoint[];
  height?: number;
  bands?: number[];
}) {
  const data = points.map((point, index) => ({
    index,
    tci: point.tci,
    state: point.state,
    time: point.observed_at
      ? new Date(point.observed_at).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })
      : `#${index}`,
    trigger: point.trigger,
  }));

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: -18 }}>
        <defs>
          <linearGradient id="tciFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.55} />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
        <XAxis
          dataKey="time"
          tick={{ fill: '#64748b', fontSize: 10 }}
          stroke="#334155"
          minTickGap={28}
        />
        <YAxis
          domain={[0, 100]}
          tick={{ fill: '#64748b', fontSize: 10 }}
          stroke="#334155"
          width={44}
        />
        {bands.map((band) => (
          <ReferenceLine
            key={band}
            y={band}
            stroke="#475569"
            strokeDasharray="4 4"
            label={{ value: String(band), fill: '#475569', fontSize: 9, position: 'right' }}
          />
        ))}
        <Tooltip
          contentStyle={{
            backgroundColor: '#0f172a',
            border: '1px solid #334155',
            borderRadius: 8,
            fontSize: 12,
          }}
          labelStyle={{ color: '#94a3b8' }}
          formatter={(value: number, _name, item) => [
            `${value.toFixed(1)} (${(item?.payload as { state?: string })?.state ?? ''})`,
            'TCI',
          ]}
        />
        <Area
          type="monotone"
          dataKey="tci"
          stroke="#38bdf8"
          strokeWidth={2}
          fill="url(#tciFill)"
          isAnimationActive={false}
          dot={false}
          activeDot={{ r: 3 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
