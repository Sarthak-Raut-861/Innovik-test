import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

import { TrustPulseClient, deviceFingerprint } from '../trustpulse-sdk';
import { getApiKey, getTenantId, login, sendTelemetry } from '../services/api';
import type { LoginResponse, TrustResult } from '../types/trust';
import { ConfidencePill, StateBadge, TrendIndicator } from '../components/Badges';
import { FactorBars } from '../components/FactorBars';
import { EvidenceList } from '../components/EvidenceList';
import { KeyValue, Panel } from '../components/Layout';
import { TciGauge } from '../components/TciGauge';

/**
 * TrustDev — a simulated enterprise developer/cloud administration console.
 *
 * It exists to show that TRUSTPULSE is application-agnostic: TrustDev only
 * reports *what the user did*; all scoring happens in TRUSTPULSE.
 *
 * Prototype caveat: this demo calls TRUSTPULSE straight from the browser so the
 * whole loop runs with one command. A real integration performs action
 * evaluation server-to-server and the browser never holds the API key.
 */

const DEMO_USERS = [
  { username: 'alice.chen', label: 'Alice Chen — Admin (MFA)', password: 'TrustDemo!234' },
  { username: 'marcus.reed', label: 'Marcus Reed — Developer', password: 'TrustDemo!234' },
  { username: 'priya.nair', label: 'Priya Nair — SOC Analyst (MFA)', password: 'TrustDemo!234' },
];

/** Derived features used by the demo simulator (never raw events). */
const NORMAL_FEATURES = {
  typing: {
    meanDwellTime: 114,
    dwellStdDev: 25,
    meanFlightTime: 90,
    flightStdDev: 30,
    typingSpeed: 6.0,
    pauseRate: 0.13,
  },
  mouse: {
    meanVelocity: 830,
    velocityStdDev: 255,
    meanAcceleration: 2150,
    directionChangeRate: 3.3,
    totalDistance: 18000,
    movementDuration: 4100,
    meanPauseTime: 335,
  },
  click: { clickCount: 17, meanInterval: 930, intervalStdDev: 300, clickFrequency: 1.1 },
  scroll: {
    meanVelocity: 1520,
    totalDistance: 9100,
    meanPauseDuration: 610,
    eventRate: 6.1,
  },
};

const ATTACKER_FEATURES = {
  typing: {
    meanDwellTime: 380,
    dwellStdDev: 12,
    meanFlightTime: 300,
    flightStdDev: 9,
    typingSpeed: 2.1,
    pauseRate: 0.02,
  },
  mouse: {
    meanVelocity: 9000,
    velocityStdDev: 60,
    meanAcceleration: 41000,
    directionChangeRate: 0.4,
    totalDistance: 92000,
    movementDuration: 900,
    meanPauseTime: 40,
  },
  click: { clickCount: 64, meanInterval: 155, intervalStdDev: 12, clickFrequency: 6.4 },
  scroll: {
    meanVelocity: 18000,
    totalDistance: 240000,
    meanPauseDuration: 30,
    eventRate: 42,
  },
};

interface LogEntry {
  at: string;
  kind: 'info' | 'trust' | 'error';
  text: string;
}

export function TrustDevApp() {
  const [username, setUsername] = useState(DEMO_USERS[0].username);
  const [password, setPassword] = useState(DEMO_USERS[0].password);
  const [mfaCode, setMfaCode] = useState('123456');
  const [session, setSession] = useState<LoginResponse | null>(null);
  const [trust, setTrust] = useState<TrustResult | null>(null);
  const [log, setLog] = useState<LogEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const clientRef = useRef<TrustPulseClient | null>(null);

  const append = (kind: LogEntry['kind'], text: string) =>
    setLog((current) =>
      [...current, { at: new Date().toLocaleTimeString(), kind, text }].slice(-60),
    );

  useEffect(() => () => clientRef.current?.stop(), []);

  const handleLogin = async () => {
    setBusy(true);
    try {
      const device = deviceFingerprint();
      const response = await login({
        username,
        password,
        mfa_code: mfaCode || undefined,
        device: { ...device, label: 'trustdev-browser' },
        network: { country: 'US', asn: 'AS15169' },
      });
      setSession(response);
      setTrust(response.trust);
      append(
        'trust',
        `Session opened · TCI ${response.trust.tci.toFixed(1)} · ${response.trust.state}`,
      );

      const client = new TrustPulseClient({
        apiKey: getApiKey(),
        tenantId: getTenantId(),
        flushIntervalMs: 6000,
        onTrustUpdate: (result) => setTrust(result as TrustResult),
        onError: (error) => append('error', `SDK telemetry failed: ${String(error)}`),
      });
      clientRef.current?.stop();
      client.start(response.session.session_id);
      clientRef.current = client;
      append('info', 'TRUSTPULSE SDK attached — collecting derived interaction features');
    } catch (error) {
      append('error', error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const emit = async (label: string, features: Record<string, unknown>, source: 'SDK' | 'SIMULATION') => {
    if (!session) return;
    setBusy(true);
    try {
      const response = await sendTelemetry({
        session_id: session.session.session_id,
        features,
        source,
      });
      setTrust(response.trust);
      append(
        'trust',
        `${label} · anomaly ${response.anomaly_score.toFixed(2)} · TCI ${response.trust.tci.toFixed(1)} · ${response.trust.state}`,
      );
    } catch (error) {
      append('error', error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  if (!session) {
    return (
      <div className="mx-auto max-w-md space-y-5">
        <div>
          <Link to="/soc" className="btn-ghost mb-4">
            ← SOC dashboard
          </Link>
          <h1 className="text-2xl font-semibold tracking-tight">TrustDev</h1>
          <p className="mt-1 text-sm text-slate-500">
            Simulated enterprise developer &amp; cloud administration console. Signing in opens a
            TRUSTPULSE session and starts continuous trust evaluation.
          </p>
        </div>

        <Panel title="Sign in">
          <div className="space-y-3">
            <label className="block">
              <span className="card-title">User</span>
              <select
                className="input mt-1"
                value={username}
                onChange={(event) => {
                  const next = DEMO_USERS.find((user) => user.username === event.target.value);
                  setUsername(event.target.value);
                  if (next) setPassword(next.password);
                }}
              >
                {DEMO_USERS.map((user) => (
                  <option key={user.username} value={user.username}>
                    {user.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="card-title">Password</span>
              <input
                className="input mt-1"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
            <label className="block">
              <span className="card-title">MFA code (required for MFA accounts)</span>
              <input
                className="input mt-1"
                value={mfaCode}
                onChange={(event) => setMfaCode(event.target.value)}
                placeholder="123456"
              />
            </label>
            <button className="btn-primary w-full justify-center" onClick={handleLogin} disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in to TrustDev'}
            </button>
            <p className="text-[11px] leading-relaxed text-slate-600">
              Passwords are verified against a salted PBKDF2 digest and are never stored or logged.
              TRUSTPULSE records <em>how</em> you authenticated; it does not replace MFA or your IdP.
            </p>
          </div>
        </Panel>

        {log.length > 0 ? (
          <Panel title="Console">
            <ul className="space-y-1 font-mono text-[11px]">
              {log.map((entry, index) => (
                <li
                  key={index}
                  className={
                    entry.kind === 'error'
                      ? 'text-rose-300'
                      : entry.kind === 'trust'
                        ? 'text-cyan-300'
                        : 'text-slate-400'
                  }
                >
                  {entry.at} · {entry.text}
                </li>
              ))}
            </ul>
          </Panel>
        ) : null}
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">
            TrustDev <span className="text-slate-600">/ {session.session.username}</span>
          </h1>
          <p className="mt-1 font-mono text-xs text-slate-500">
            session {session.session.session_id} · {session.session.auth_method} ·{' '}
            {session.session.status}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link to="/soc" className="btn-ghost">
            SOC dashboard
          </Link>
          <Link
            to={`/soc/sessions/${encodeURIComponent(session.session.session_id)}`}
            className="btn-ghost"
          >
            Session detail
          </Link>
        </div>
      </header>

      <div className="grid gap-5 lg:grid-cols-3">
        <Panel title="Live trust" className="lg:col-span-1">
          <div className="flex flex-col items-center gap-3">
            <TciGauge tci={trust?.tci ?? null} state={trust?.state ?? 'TRUSTED'} size={170} />
            <div className="flex items-center gap-2">
              {trust ? <ConfidencePill confidence={trust.confidence} /> : null}
              {trust ? <TrendIndicator trend={trust.trend} /> : null}
              {trust ? <StateBadge state={trust.state} size="sm" /> : null}
            </div>
            <div className="w-full">
              <KeyValue label="Evaluations" value={trust?.evaluations ?? 0} />
              <KeyValue label="SDK collecting" value={clientRef.current?.isRunning ? 'yes' : 'no'} />
              <KeyValue label="Last trigger" value={trust?.trigger ?? '–'} />
            </div>
          </div>
        </Panel>

        <Panel title="Demo controls" subtitle="Deterministic simulation — no real attacker needed." className="lg:col-span-2">
          <div className="flex flex-wrap gap-2">
            <button
              className="btn-ghost"
              disabled={busy}
              onClick={() => emit('Normal interaction', NORMAL_FEATURES, 'SIMULATION')}
            >
              Emit normal behavior
            </button>
            <button
              className="btn-danger"
              disabled={busy}
              onClick={() => emit('Simulated session takeover', ATTACKER_FEATURES, 'SIMULATION')}
            >
              Simulate takeover behavior
            </button>
            <button
              className="btn-ghost"
              disabled={busy}
              onClick={() => clientRef.current?.flush()}
            >
              Flush live SDK features
            </button>
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-slate-500">
            These controls send <strong>derived aggregate features only</strong>. Action risk,
            policy decisions, step-up and containment arrive in Phase 2; proof and the full attack
            demo arrive in Phase 3.
          </p>
          <div className="mt-4">
            <div className="card-title mb-2">Factor breakdown</div>
            <FactorBars factors={trust?.factors ?? []} />
          </div>
        </Panel>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="Evidence" subtitle="Why trust is at this level right now.">
          <EvidenceList evidence={trust?.evidence ?? []} />
        </Panel>
        <Panel title="Console">
          <ul className="max-h-72 space-y-1 overflow-y-auto font-mono text-[11px]">
            {log.map((entry, index) => (
              <li
                key={index}
                className={
                  entry.kind === 'error'
                    ? 'text-rose-300'
                    : entry.kind === 'trust'
                      ? 'text-cyan-300'
                      : 'text-slate-400'
                }
              >
                {entry.at} · {entry.text}
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
