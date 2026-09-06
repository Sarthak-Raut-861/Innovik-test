import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import {
  ApiError,
  getTrustHistory,
  getSocSessionDetail,
  type TrustHistory,
} from '../services/api';
import type { SocSessionDetail } from '../types/trust';
import { ConfidencePill, DecisionBadge, RiskBadge, StateBadge, TrendIndicator } from '../components/Badges';
import { EvidenceList } from '../components/EvidenceList';
import { FactorBars } from '../components/FactorBars';
import { EmptyState, KeyValue, Panel } from '../components/Layout';
import { TciGauge } from '../components/TciGauge';
import { TciHistoryChart } from '../components/TciHistoryChart';

const REFRESH_MS = 3000;

/** Full analyst view of one session: why trust is what it is, and what happened. */
export function SessionDetail() {
  const { sessionId = '' } = useParams<{ sessionId: string }>();
  const [detail, setDetail] = useState<SocSessionDetail | null>(null);
  const [history, setHistory] = useState<TrustHistory | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!sessionId) return;
    try {
      const [nextDetail, nextHistory] = await Promise.all([
        getSocSessionDetail(sessionId),
        getTrustHistory(sessionId),
      ]);
      setDetail(nextDetail);
      setHistory(nextHistory);
      setError(null);
    } catch (caught) {
      setError(
        caught instanceof ApiError ? `${caught.message} (${caught.status})` : 'Failed to load session',
      );
    }
  }, [sessionId]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

  if (error) {
    return (
      <div className="space-y-4">
        <Link to="/soc" className="btn-ghost">
          ← Back to SOC
        </Link>
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      </div>
    );
  }

  if (!detail) {
    return <p className="text-sm text-slate-500">Loading session…</p>;
  }

  const { session, trust, baselines } = detail;

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Link to="/soc" className="btn-ghost">
            ← SOC
          </Link>
          <div>
            <h1 className="font-mono text-lg text-slate-100">{session.session_id}</h1>
            <p className="text-xs text-slate-500">
              {session.user ?? 'unknown user'} · {session.device ?? 'unknown device'} ·{' '}
              {session.status}
            </p>
          </div>
        </div>
        {trust ? (
          <div className="flex items-center gap-3">
            <ConfidencePill confidence={trust.confidence} />
            <TrendIndicator trend={trust.trend} />
            <StateBadge state={trust.state} />
          </div>
        ) : null}
      </header>

      <div className="grid gap-5 lg:grid-cols-3">
        <Panel title="Trust Confidence Index">
          <div className="flex flex-col items-center gap-3">
            <TciGauge tci={session.tci ?? null} state={trust?.state ?? session.trust_state} />
            <div className="w-full">
              <KeyValue label="Evaluations" value={trust?.evaluations ?? 0} />
              <KeyValue label="Trigger" value={trust?.trigger ?? '–'} />
              <KeyValue label="Raw band" value={trust?.raw_band ?? '–'} />
              <KeyValue
                label="Hysteresis"
                value={trust?.hysteresis_applied ? 'applied' : 'not applied'}
              />
              <KeyValue
                label="Last change"
                value={
                  trust?.state_changed && trust.previous_state
                    ? `${trust.previous_state} → ${trust.state}`
                    : 'no change'
                }
              />
            </div>
            {trust && trust.warnings.length > 0 ? (
              <div className="mt-2 w-full space-y-1">
                {trust.warnings.map((warning) => (
                  <div
                    key={warning}
                    className="rounded bg-amber-500/10 px-2 py-1 font-mono text-[10px] text-amber-300"
                  >
                    {warning}
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        </Panel>

        <Panel
          title="Factor breakdown"
          subtitle="T_t = F(I, D, B, N, C, H) — weights are configurable."
          className="lg:col-span-2"
        >
          <FactorBars factors={trust?.factors ?? []} />
        </Panel>
      </div>

      <Panel title="TCI history" subtitle="Dashed lines are the configured state boundaries.">
        {history && history.points.length > 0 ? (
          <TciHistoryChart points={history.points} />
        ) : (
          <EmptyState message="No evaluations recorded yet." />
        )}
      </Panel>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel
          title="Evidence"
          subtitle="Why trust is at this level — generated by the trust engine, never by the model alone."
        >
          <EvidenceList evidence={detail.evidence} />
        </Panel>

        <div className="space-y-5">
          <Panel title="Actions" subtitle="Sensitive actions attempted in this session.">
            {detail.actions.length === 0 ? (
              <EmptyState message="No sensitive actions attempted yet." />
            ) : (
              <ul className="space-y-2">
                {detail.actions.map((action) => (
                  <li
                    key={action.id}
                    className="flex items-center justify-between gap-3 rounded-lg border border-slate-800 px-3 py-2"
                  >
                    <div>
                      <div className="font-mono text-xs text-slate-200">{action.action}</div>
                      <div className="text-[10px] text-slate-500">
                        {action.resource ?? 'no resource'} · TCI{' '}
                        {action.tci_at_decision?.toFixed(1) ?? '–'} ·{' '}
                        {action.trust_state_at_decision ?? '–'}
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <RiskBadge risk={action.action_risk} />
                      <DecisionBadge decision={action.decision} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel
            title="Baselines"
            subtitle="Trusted Core moves slowly; the Adaptive Shadow absorbs drift and is promotion-gated."
          >
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="card-title mb-2">Trusted Core</div>
                <KeyValue label="Observations" value={baselines.core.observations} />
                <KeyValue label="Features" value={baselines.core.features} />
                <KeyValue label="Version" value={baselines.core.version} />
                <KeyValue label="Promotions" value={baselines.core.promotions_from_shadow} />
                <KeyValue label="Rejected obs." value={baselines.core.rejected_observations} />
              </div>
              <div>
                <div className="card-title mb-2">Adaptive Shadow</div>
                <KeyValue label="Observations" value={baselines.shadow.observations} />
                <KeyValue label="Features" value={baselines.shadow.features} />
                <KeyValue label="Version" value={baselines.shadow.version} />
                <KeyValue label="Rejected obs." value={baselines.shadow.rejected_observations} />
              </div>
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-slate-500">
              Observations from SUSPICIOUS or worse sessions are counted as rejected and never
              reach the Trusted Core — this is the baseline-poisoning guard.
            </p>
          </Panel>
        </div>
      </div>

      <Panel title="State timeline" subtitle="Trust-state transitions, with what triggered each one.">
        {history && history.state_timeline.length > 0 ? (
          <ul className="space-y-2">
            {history.state_timeline.map((transition, index) => (
              <li
                key={`${transition.observed_at}-${index}`}
                className="flex items-center gap-3 rounded-lg border border-slate-800 px-3 py-2 text-xs"
              >
                <span className="font-mono text-slate-500">
                  {transition.observed_at ? new Date(transition.observed_at).toLocaleTimeString() : '–'}
                </span>
                <span className="font-mono text-slate-300">
                  {transition.from ?? '–'} → <span className="text-cyan-300">{transition.to}</span>
                </span>
                <span className="font-mono text-slate-500">TCI {transition.tci.toFixed(1)}</span>
                <span className="ml-auto font-mono text-[10px] uppercase text-slate-600">
                  {transition.trigger}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState message="No state transitions yet." />
        )}
      </Panel>
    </div>
  );
}
