/**
 * TRUSTPULSE shared data contracts.
 *
 * These mirror the backend Pydantic schemas in `backend/app/schemas/trust.py`
 * and `shared/schemas/trust.ts`. Keep them in sync — `tests/test_shared_contract.py`
 * fails the build if the backend and the shared JSON disagree.
 */

export type TrustState =
  | 'TRUSTED'
  | 'DEGRADED'
  | 'SUSPICIOUS'
  | 'CRITICAL'
  | 'BLOCKED'
  | 'CONTAINED';

export type Trend = 'RISING' | 'STABLE' | 'FALLING' | 'INSUFFICIENT_DATA';
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';
/**
 * A decision the Policy Enforcement Point can return.
 *
 * There is no PENDING: the PEP always terminates in a verdict. The neutral
 * badge style in DecisionBadge is a fallback for unrecognised values, not an
 * API state.
 */
export type Decision = 'ALLOW' | 'STEP_UP' | 'BLOCK' | 'REVOKE' | 'CONTAIN';

export interface EvidenceRecord {
  type: string;
  severity: number;
  description: string;
  source: string;
  observed_at?: string | null;
  metadata?: Record<string, unknown>;
}

export interface FactorScore {
  name: 'identity' | 'device' | 'behavior' | 'network' | 'session' | 'history';
  score: number;
  configured_weight: number;
  effective_weight: number;
  available: boolean;
  contribution: number;
  reasons: string[];
  detail?: Record<string, unknown>;
}

/** TCI is an engineering trust index on a 0-100 scale — NOT a probability. */
export interface TrustResult {
  session_id: string;
  tci: number;
  confidence: Confidence;
  trend: Trend;
  state: TrustState;
  previous_state?: TrustState | null;
  state_changed: boolean;
  raw_band?: string | null;
  hysteresis_applied: boolean;
  factors: FactorScore[];
  evidence: EvidenceRecord[];
  warnings: string[];
  evaluations: number;
  evaluated_at?: string | null;
  trigger: string;
}

export interface SessionInfo {
  session_id: string;
  status: string;
  user_id?: string | null;
  username?: string | null;
  device_id?: string | null;
  device_fingerprint?: string | null;
  application_id: string;
  auth_method: string;
  mfa_used: boolean;
  tci?: number | null;
  confidence: Confidence;
  trend: Trend;
  trust_state: TrustState;
  evaluations: number;
  is_contained: boolean;
  created_at: string;
  last_seen_at: string;
  trust?: TrustResult | null;
}

export interface LoginResponse {
  session: SessionInfo;
  token: string;
  trust: TrustResult;
}

export interface TelemetryResponse {
  accepted: boolean;
  features_received: number;
  anomaly_score: number;
  trust: TrustResult;
  learned: {
    shadow_learned?: boolean;
    shadow_rejected?: boolean;
    core_observations?: number;
    shadow_observations?: number;
    promotion?: Record<string, unknown>;
  };
  rejected_reason?: string | null;
}

export interface SocOverview {
  active_sessions: number;
  suspicious_sessions: number;
  contained_sessions: number;
  open_incidents: number;
  average_tci: number | null;
  blocked_actions: number;
  step_up_requests: number;
  trust_model_version: string;
  disclaimer: string;
}

export interface SocSessionSummary {
  session_id: string;
  user?: string | null;
  user_id?: string | null;
  device?: string | null;
  tci?: number | null;
  trust_state: TrustState;
  trend: Trend;
  confidence: Confidence;
  last_action?: string | null;
  action_risk?: number | null;
  decision?: string | null;
  last_seen_at: string;
  status: string;
  is_contained: boolean;
}

export interface TrustHistoryPoint {
  observed_at: string | null;
  tci: number;
  state: TrustState;
  confidence: Confidence;
  trend: Trend;
  trigger: string;
  state_changed: boolean;
}

export interface SocSessionDetail {
  session: SocSessionSummary;
  trust: TrustResult | null;
  tci_history: TrustHistoryPoint[];
  evidence: EvidenceRecord[];
  actions: Array<{
    id: string;
    action: string;
    resource?: string | null;
    action_risk: number;
    decision: string;
    decision_reason?: string | null;
    tci_at_decision?: number | null;
    trust_state_at_decision?: string | null;
    receipt_id?: string | null;
    step_up_result?: string | null;
    requested_at: string | null;
  }>;
  baselines: {
    core: {
      observations: number;
      version: number;
      features: number;
      promotions_from_shadow: number;
      rejected_observations: number;
    };
    shadow: {
      observations: number;
      version: number;
      features: number;
      rejected_observations: number;
      last_promotion_reasons?: unknown;
    };
  };
  incidents: unknown[];
}

export interface TrustModelInfo {
  schema_version: string;
  source: string;
  weights: Record<string, number>;
  state_bands: Array<{ state: string; min: number }>;
  hysteresis: Record<string, unknown>;
  action_risk_profiles: Record<string, Record<string, unknown>>;
  evidence_types: string[];
  disclaimer: string;
}

export interface ActionRiskProfile {
  action: string;
  risk: number;
  sensitivity: number;
  privilege: number;
  resource_exposure: number;
  impact: number;
  category: string;
  source?: string;
}

export interface UserSummary {
  id: string;
  external_user_id: string;
  username: string;
  display_name?: string | null;
  role: string;
  mfa_enabled: boolean;
  is_active: boolean;
}

export interface DeviceSummary {
  id: string;
  device_fingerprint: string;
  label?: string | null;
  platform?: string | null;
  browser?: string | null;
  trust_level: string;
  is_registered: boolean;
  is_flagged: boolean;
  observation_count: number;
  last_seen_at: string;
}

/** Trust-state ordering used across the UI. */
export const STATE_SEVERITY: Record<TrustState, number> = {
  TRUSTED: 0,
  DEGRADED: 1,
  SUSPICIOUS: 2,
  CRITICAL: 3,
  BLOCKED: 4,
  CONTAINED: 5,
};

export const STATE_COLOR: Record<TrustState, string> = {
  TRUSTED: '#22c55e',
  DEGRADED: '#eab308',
  SUSPICIOUS: '#f97316',
  CRITICAL: '#ef4444',
  BLOCKED: '#b91c1c',
  CONTAINED: '#a855f7',
};

export const FACTOR_LABEL: Record<string, string> = {
  identity: 'Identity assurance',
  device: 'Device trust',
  behavior: 'Behavioral confidence',
  network: 'Network / context',
  session: 'Session context',
  history: 'Historical evidence',
};

export const TCI_DISCLAIMER =
  'TCI is an engineering trust index on a 0–100 scale. It is not a probability, ' +
  'and all weights and thresholds are configurable prototype parameters.';
