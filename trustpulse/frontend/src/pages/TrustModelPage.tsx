import { useEffect, useState } from 'react';

import { getActionCatalogue, getTrustModel } from '../services/api';
import type { ActionRiskProfile, TrustModelInfo } from '../types/trust';
import { KeyValue, Panel } from '../components/Layout';

/**
 * Transparency page: the live weights, thresholds, hysteresis and action risk
 * catalogue actually in force. An analyst must be able to see the parameters
 * that produced a decision.
 */
export function TrustModelPage() {
  const [model, setModel] = useState<TrustModelInfo | null>(null);
  const [actions, setActions] = useState<Record<string, ActionRiskProfile>>({});
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([getTrustModel(), getActionCatalogue()])
      .then(([nextModel, nextActions]) => {
        setModel(nextModel);
        setActions(nextActions.actions);
      })
      .catch((caught: unknown) =>
        setError(caught instanceof Error ? caught.message : 'Failed to load configuration'),
      );
  }, []);

  if (error) {
    return (
      <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
        {error}
      </div>
    );
  }
  if (!model) return <p className="text-sm text-slate-500">Loading configuration…</p>;

  const rows = Object.entries(actions);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Trust model</h1>
        <p className="mt-1 text-sm text-slate-500">
          Live configuration served by the backend (schema v{model.schema_version}). Every value
          can be overridden by environment or a tenant profile — nothing is hard-coded in the
          engines.
        </p>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="TCI factor weights" subtitle="T_t = F(I, D, B, N, C, H)">
          {Object.entries(model.weights).map(([name, weight]) => (
            <KeyValue key={name} label={name} value={`${(weight * 100).toFixed(0)}%`} />
          ))}
          <p className="mt-3 text-[11px] leading-relaxed text-slate-500">{model.disclaimer}</p>
        </Panel>

        <Panel title="Trust state bands & hysteresis">
          {model.state_bands.map((band) => (
            <KeyValue key={band.state} label={band.state} value={`TCI ≥ ${band.min}`} />
          ))}
          <div className="mt-3 border-t border-slate-800 pt-3">
            {Object.entries(model.hysteresis).map(([key, value]) => (
              <KeyValue
                key={key}
                label={key}
                value={Array.isArray(value) ? value.join(', ') : String(value)}
              />
            ))}
          </div>
        </Panel>
      </div>

      <Panel
        title="Action risk catalogue"
        subtitle="Risk describes the action, not the user. Authorization combines it with session trust in the policy engine (Phase 2)."
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                <th className="px-3 py-2">Action</th>
                <th className="px-3 py-2">Risk</th>
                <th className="px-3 py-2">Sensitivity</th>
                <th className="px-3 py-2">Privilege</th>
                <th className="px-3 py-2">Exposure</th>
                <th className="px-3 py-2">Impact</th>
                <th className="px-3 py-2">Category</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(([name, profile]) => (
                <tr key={name} className="table-row">
                  <td className="px-3 py-2 font-mono text-xs text-slate-200">{name}</td>
                  <td className="px-3 py-2 font-mono tabular-nums text-slate-100">{profile.risk}</td>
                  <td className="px-3 py-2 font-mono text-xs text-slate-400">
                    {profile.sensitivity.toFixed(2)}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-slate-400">
                    {profile.privilege.toFixed(2)}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-slate-400">
                    {profile.resource_exposure.toFixed(2)}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-slate-400">
                    {profile.impact.toFixed(2)}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-slate-500">
                    {profile.category}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Evidence types" subtitle="Vocabulary the trust engine may emit.">
        <div className="flex flex-wrap gap-2">
          {model.evidence_types.map((type) => (
            <span
              key={type}
              className="rounded border border-slate-700 bg-slate-800/60 px-2 py-1 font-mono text-[10px] text-slate-300"
            >
              {type}
            </span>
          ))}
        </div>
        <p className="mt-3 font-mono text-[11px] text-slate-600">source: {model.source}</p>
      </Panel>
    </div>
  );
}
