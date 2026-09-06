import { Link } from 'react-router-dom';

import type { SocSessionSummary } from '../types/trust';
import { DecisionBadge, RiskBadge, StateBadge, TrendIndicator } from './Badges';
import { EmptyState } from './Layout';

/** SOC session table: one row per session with the decision-relevant columns. */
export function SessionTable({
  sessions,
  activeSessionId,
}: {
  sessions: SocSessionSummary[];
  activeSessionId?: string;
}) {
  if (sessions.length === 0) {
    return <EmptyState message="No sessions yet. Log in to TrustDev to create one." />;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
            <th className="px-3 py-2 font-medium">Session</th>
            <th className="px-3 py-2 font-medium">User</th>
            <th className="px-3 py-2 font-medium">Device</th>
            <th className="px-3 py-2 font-medium">TCI</th>
            <th className="px-3 py-2 font-medium">Trust state</th>
            <th className="px-3 py-2 font-medium">Trend</th>
            <th className="px-3 py-2 font-medium">Last action</th>
            <th className="px-3 py-2 font-medium">Risk</th>
            <th className="px-3 py-2 font-medium">Decision</th>
            <th className="px-3 py-2 font-medium">Last seen</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((session) => {
            const isActive = session.session_id === activeSessionId;
            return (
              <tr
                key={session.session_id}
                className={`table-row ${isActive ? 'bg-cyan-500/5' : ''}`}
              >
                <td className="px-3 py-2">
                  <Link
                    to={`/soc/sessions/${encodeURIComponent(session.session_id)}`}
                    className="font-mono text-xs text-cyan-300 hover:text-cyan-200 hover:underline"
                  >
                    {session.session_id.slice(0, 18)}
                  </Link>
                  {session.is_contained ? (
                    <span className="ml-2 rounded bg-fuchsia-500/15 px-1.5 py-0.5 text-[9px] uppercase text-fuchsia-300">
                      contained
                    </span>
                  ) : null}
                </td>
                <td className="px-3 py-2 text-slate-300">{session.user ?? '–'}</td>
                <td className="px-3 py-2 font-mono text-xs text-slate-400">
                  {session.device ?? '–'}
                </td>
                <td className="px-3 py-2 font-mono tabular-nums text-slate-100">
                  {session.tci === null || session.tci === undefined
                    ? '–'
                    : session.tci.toFixed(1)}
                </td>
                <td className="px-3 py-2">
                  <StateBadge state={session.trust_state} size="sm" />
                </td>
                <td className="px-3 py-2">
                  <TrendIndicator trend={session.trend} />
                </td>
                <td className="px-3 py-2 font-mono text-xs text-slate-400">
                  {session.last_action ?? '–'}
                </td>
                <td className="px-3 py-2">
                  <RiskBadge risk={session.action_risk} />
                </td>
                <td className="px-3 py-2">
                  <DecisionBadge decision={session.decision} />
                </td>
                <td className="px-3 py-2 font-mono text-[11px] text-slate-500">
                  {new Date(session.last_seen_at).toLocaleTimeString()}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
