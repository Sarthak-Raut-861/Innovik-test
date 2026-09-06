import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { ApiError, getSocOverview, getSocSessions } from '../services/api';
import type { SocOverview, SocSessionSummary } from '../types/trust';
import { Panel, StatCard } from '../components/Layout';
import { SessionTable } from '../components/SessionTable';

const REFRESH_MS = 4000;

/**
 * SOC dashboard.
 *
 * Polling is used in Phase 1; Phase 3 replaces it with the WebSocket feed at
 * `/api/v1/ws/soc` so updates arrive without a refresh.
 */
export function Dashboard({ activeSessionId }: { activeSessionId?: string }) {
  const [overview, setOverview] = useState<SocOverview | null>(null);
  const [sessions, setSessions] = useState<SocSessionSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [nextOverview, nextSessions] = await Promise.all([
        getSocOverview(),
        getSocSessions(50),
      ]);
      setOverview(nextOverview);
      setSessions(nextSessions);
      setUpdatedAt(new Date());
      setError(null);
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? `${caught.message} (${caught.status})`
          : 'Cannot reach the TRUSTPULSE API. Is the backend running?',
      );
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">
            Security Operations
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            Continuous session trust across every protected application.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-500">
          {updatedAt ? (
            <span className="font-mono">updated {updatedAt.toLocaleTimeString()}</span>
          ) : null}
          <Link to="/trustdev" className="btn-ghost">
            Open TrustDev
          </Link>
        </div>
      </header>

      {error ? (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        <StatCard label="Active sessions" value={overview?.active_sessions ?? '–'} />
        <StatCard
          label="Suspicious"
          value={overview?.suspicious_sessions ?? '–'}
          tone={(overview?.suspicious_sessions ?? 0) > 0 ? 'warn' : 'good'}
        />
        <StatCard
          label="Critical incidents"
          value={overview?.open_incidents ?? '–'}
          tone={(overview?.open_incidents ?? 0) > 0 ? 'bad' : 'good'}
        />
        <StatCard
          label="Average TCI"
          value={
            overview?.average_tci === null || overview?.average_tci === undefined
              ? '–'
              : overview.average_tci.toFixed(1)
          }
          tone={
            (overview?.average_tci ?? 100) < 50
              ? 'bad'
              : (overview?.average_tci ?? 100) < 75
                ? 'warn'
                : 'good'
          }
        />
        <StatCard
          label="Blocked actions"
          value={overview?.blocked_actions ?? '–'}
          tone={(overview?.blocked_actions ?? 0) > 0 ? 'bad' : 'default'}
        />
        <StatCard label="Step-up requests" value={overview?.step_up_requests ?? '–'} />
      </div>

      <Panel
        title="Sessions"
        subtitle="Every session TRUSTPULSE is currently scoring, newest activity first."
        right={
          <span className="font-mono text-[11px] text-slate-500">
            trust model v{overview?.trust_model_version ?? '?'}
          </span>
        }
      >
        <SessionTable sessions={sessions} activeSessionId={activeSessionId} />
      </Panel>

      {overview?.disclaimer ? (
        <p className="px-1 text-xs leading-relaxed text-slate-600">{overview.disclaimer}</p>
      ) : null}
    </div>
  );
}
