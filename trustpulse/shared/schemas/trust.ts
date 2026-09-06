/**
 * TRUSTPULSE shared contracts — canonical TypeScript definitions.
 *
 * This file is the contract between the backend, the browser SDK and any
 * customer integration. The backend Pydantic schemas in
 * `backend/app/schemas/trust.py` are the runtime authority; this mirror exists
 * so TypeScript consumers share one vocabulary instead of retyping it.
 *
 * Keep in sync with:
 *   - backend/app/schemas/trust.py
 *   - backend/app/schemas/platform.py
 *   - shared/constants/trust_model.json
 *   - frontend/src/types/trust.ts (re-exports these for the dashboard)
 */

// ----------------------------------------------------------------- trust core

/** Trust states, ordered least to most severe. */
export type TrustState =
  | 'TRUSTED'
  | 'DEGRADED'
  | 'SUSPICIOUS'
  | 'CRITICAL'
  | 'BLOCKED'
  | 'CONTAINED';

/** Direction of travel of the TCI across recent evaluations. */
export type Trend = 'RISING' | 'STABLE' | 'FALLING' | 'INSUFFICIENT_DATA';

/**
 * How much evidence backs the score — independent of the score itself.
 * A login can legitimately be TRUSTED with LOW confidence.
 */
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';

/** The six TCI factor names. */
export type FactorName =
  | 'identity'
  | 'device'
  | 'behavior'
  | 'network'
  | 'session'
  | 'history';

/**
 * Evidence vocabulary the trust engine may emit.
 *
 * Mirrors `evidence_types` in shared/constants/trust_model.json exactly.
 * Note that `FACTOR_UNAVAILABLE` is NOT an evidence type — it appears only as a
 * warning string prefix (`FACTOR_UNAVAILABLE:network`) in `TrustResult.warnings`.
 */
export type EvidenceType =
  | 'BEHAVIOR_DEVIATION'
  | 'DEVICE_CHANGE'
  | 'NETWORK_CHANGE'
  | 'SESSION_ANOMALY'
  | 'UNUSUAL_ACTION'
  | 'BASELINE_DEVIATION'
  | 'PRIVILEGE_ESCALATION'
  | 'IDENTITY_ASSURANCE_DROP'
  | 'HISTORY_RISK'
  | 'COLD_START'
  | 'TELEMETRY_GAP'
  | 'STATE_CHANGE';

export interface EvidenceRecord {
  type: string;
  /** 0-1. Persisted as a security event at >= 0.35. */
  severity: number;
  description: string;
  source: string;
  observed_at?: string | null;
  metadata?: Record<string, unknown>;
}

export interface FactorScore {
  name: FactorName;
  score: number;
  /** Weight as configured in trust_model.json. */
  configured_weight: number;
  /**
   * Weight actually applied. Differs from `configured_weight` when another
   * factor is unavailable: available weights are renormalised so a blind spot
   * is excluded rather than scored as distrust.
   */
  effective_weight: number;
  /** False when there is no evidence for this factor at all. */
  available: boolean;
  /** effective_weight * score — the factor's contribution to the TCI. */
  contribution: number;
  reasons: string[];
  detail?: Record<string, unknown>;
}

/**
 * The shared trust result.
 *
 * `tci` is an engineering trust index on a 0-100 scale. It is NOT a
 * probability and must not be presented as one.
 */
export interface TrustResult {
  session_id: string;
  tci: number;
  confidence: Confidence;
  trend: Trend;
  state: TrustState;
  previous_state?: TrustState | null;
  state_changed: boolean;
  /** The band the raw TCI fell into, before hysteresis. */
  raw_band?: TrustState | null;
  hysteresis_applied: boolean;
  factors: FactorScore[];
  evidence: EvidenceRecord[];
  warnings: string[];
  evaluations: number;
  evaluated_at?: string | null;
  trigger: string;
}

// ------------------------------------------------------------------- actions

/**
 * A sensitive action a protected application wants to perform.
 *
 * Risk describes the ACTION, not the user. Authorization combines it with
 * session trust inside the server-side policy engine.
 */
export interface ActionRequest {
  session_id: string;
  user_id: string;
  action: string;
  resource?: string;
  context?: Record<string, unknown>;
}

/**
 * A decision the Policy Enforcement Point can actually return.
 *
 * There is deliberately no PENDING member: the PEP always terminates in a
 * verdict. A client that needs a "not yet decided" state must model it locally.
 */
export type Decision = 'ALLOW' | 'STEP_UP' | 'BLOCK' | 'REVOKE' | 'CONTAIN';

/** Why a decision was reached. Surfaced to the SOC analyst, never to the AI layer. */
export interface ActionDecision {
  decision: Decision;
  tci: number;
  action_risk: number;
  trust_state: TrustState;
  receipt_id?: string | null;
  reasons?: string[];
  step_up_method?: string | null;
  evaluated_at?: string | null;
}

// --------------------------------------------------------- authorization (P2)

/**
 * The decision the server-side Policy Enforcement Point actually made.
 *
 * `ActionDecision` above is the minimal contract every consumer needs. This is
 * the full `POST /api/v1/actions/evaluate` response, including the audit trail
 * that lets a SOC analyst answer "why". The AI layer recommends; only the PEP
 * enforces, so this object is the authoritative record of an authorization
 * decision.
 */
export interface EnforcementDecision {
  action_id: string;
  action: string;
  resource?: string | null;
  decision: Decision;
  reason: string;
  /** Identifier of the policy rule that produced the decision. */
  rule_id: string;
  policy_version: string;
  tci: number;
  trust_state: TrustState;
  action_risk: number;
  risk_band: RiskBand;
  /** How the risk score was composed, including named escalations. */
  risk_breakdown?: ActionRiskAssessment | null;
  /** The trust evaluation behind the decision, for the "why" view. */
  trust?: TrustResult | null;
  /** Receipt issued for this decision, present for every terminal decision. */
  receipt_id?: string | null;
  receipt?: TrustReceipt | null;
  /** Step-up challenge descriptor, present only when decision === 'STEP_UP'. */
  step_up?: StepUpChallenge | null;
  /** Containment applied by this decision, if any. */
  containment?: ContainmentAction[];
  incident_id?: string | null;
  /**
   * Every rule the engine evaluated, in order, with the reason each one did not
   * match. This is the SOC "why" view.
   */
  policy_audit: ConsideredRule[];
  warnings: string[];
}

/** How an action risk score was composed. */
export interface ActionRiskAssessment {
  action: string;
  risk: number;
  band: RiskBand;
  category: string;
  source: 'BUILTIN' | 'INFERRED';
  base_risk: number;
  /** True when context pushed the score above the declared base risk. */
  escalated: boolean;
  dimensions: Record<string, number>;
  /** Named, auditable adjustments: AMOUNT_ESCALATION, PRIVILEGE_ESCALATION, ... */
  adjustments: Array<{ code: string; delta: number; reason?: string }>;
  profile?: ActionRiskProfile | null;
}

/** A step-up challenge descriptor. The challenge itself is simulated. */
export interface StepUpChallenge {
  challenge_id: string;
  /** TRUSTPULSE requires the challenge; the integrating app or IdP performs it. */
  method: string;
  allowed_methods: string[];
  max_attempts: number;
  attempts_used: number;
  expires_in_seconds: number;
  required: boolean;
  reason?: string;
  /** Always present: TRUSTPULSE states plainly that this is a simulation. */
  note?: string;
}

/** One rule the policy engine evaluated, matched or not. */
export interface ConsideredRule {
  rule_id: string;
  decision: Decision;
  matched: boolean;
  /** Why it did not match, or that it was skipped (e.g. unknown predicate). */
  skipped?: string;
}

/** Outcome of presenting a step-up challenge back to the PEP. */
export interface StepUpResolution {
  accepted: boolean;
  challenge_id?: string | null;
  status?: 'SUCCEEDED' | 'FAILED' | 'EXPIRED' | 'NOT_FOUND' | 'ALREADY_RESOLVED';
  error?: string | null;
  attempts?: number | null;
  max_attempts?: number | null;
  exhausted?: boolean | null;
  /** True when the action risk is at or above `block_on_failure_min_risk`. */
  blocked?: boolean | null;
  tci_before?: number | null;
  tci?: number | null;
  trust_state?: TrustState | null;
  /** Configured `failure_tci_penalty`: the intent, not the observed change. */
  tci_penalty_configured?: number | null;
  /**
   * TCI points actually lost. Smaller than the configured value because the
   * session-context and history penalties are weighted, not subtracted raw.
   */
  tci_penalty_applied?: number | null;
  mfa_used?: boolean | null;
  containment: string[];
  incident_id?: string | null;
}

/** A containment action applied to a session. */
export type ContainmentAction =
  | 'REVOKE_SESSION'
  | 'INVALIDATE_TOKEN'
  | 'FLAG_DEVICE'
  | 'OPEN_INCIDENT'
  | 'SERVE_DECEPTION';

/** Result of a containment request. */
export interface ContainmentResult {
  session_id: string;
  contained: boolean;
  trust_state: TrustState;
  applied: ContainmentAction[];
  device_flagged: boolean;
  incident_id?: string | null;
  /** Always labelled. TRUSTPULSE never serves an undisclosed deception. */
  deception?: { label: string; description?: string } | null;
}

export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
/**
 * Incident lifecycle. OPEN and INVESTIGATING are the open statuses; CONTAINED,
 * RESOLVED and FALSE_POSITIVE are terminal. There is no 'CLOSED'.
 */
export type IncidentStatus =
  | 'OPEN'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE';

/** A security incident raised by enforcement. */
export interface IncidentRecord {
  id: string;
  tenant_id?: string | null;
  title: string;
  description?: string | null;
  severity: IncidentSeverity;
  status: IncidentStatus;
  session_id?: string | null;
  user_id?: string | null;
  device_id?: string | null;
  action?: string | null;
  tci_at_detection?: number | null;
  trust_state_at_detection?: TrustState | null;
  evidence_ids: string[];
  containment_actions: ContainmentAction[];
  receipt_ids: string[];
  opened_at?: string | null;
  closed_at?: string | null;
}

/** Aggregate security posture for the SOC dashboard. */
export interface SecurityPosture {
  score: number;
  grade: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR' | 'CRITICAL';
  components: Record<string, number>;
  open_incidents: number;
  contained_sessions: number;
  blocked_actions: number;
  window_hours: number;
  generated_at?: string | null;
}

/**
 * A policy rule as configured in `shared/constants/trust_model.json`.
 *
 * Rules are evaluated in order and the first match wins; the final rule must be
 * a catch-all. An unknown predicate never matches — it is skipped and recorded,
 * never silently treated as a pass.
 */
export interface PolicyRule {
  id: string;
  decision: Decision;
  reason: string;
  /**
   * Predicates, ANDed together. The names here are exactly the ones
   * `PolicyEngine._test_predicate` dispatches on — an unrecognised name does
   * not match, it is skipped and recorded, so a typo silently weakens nothing
   * but also enforces nothing.
   */
  requires?: {
    trust_state_in?: TrustState[];
    trust_state_not_in?: TrustState[];
    min_action_risk?: number;
    max_action_risk?: number;
    min_tci?: number;
    max_tci?: number;
    session_status?: string;
    session_status_not?: string;
    contained?: boolean;
    session_revoked?: boolean;
    open_incident?: boolean;
    mfa_used?: boolean;
    min_step_up_attempts?: number;
    confidence_in?: Confidence[];
    context_equals?: Record<string, string | number | boolean>;
  };
}

export type RiskBand = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ActionRiskProfile {
  action: string;
  /** 0-100, clamped. */
  risk: number;
  sensitivity: number;
  privilege: number;
  resource_exposure: number;
  impact: number;
  category: string;
  /**
   * BUILTIN when declared in the catalogue, INFERRED for undeclared actions.
   * An INFERRED profile is a conservative guess and is flagged as such.
   */
  source?: 'BUILTIN' | 'INFERRED';
}

// ------------------------------------------------------------------ telemetry

/**
 * Derived behavioral features. Aggregates only.
 *
 * Raw behavioral data — typed characters, clipboard content, element text,
 * input values — is rejected by the server with HTTP 422. This type
 * deliberately has no field that could carry it.
 */
export interface TypingFeatures {
  sampleCount?: number;
  meanDwellTime?: number;
  dwellStdDev?: number;
  meanFlightTime?: number;
  flightStdDev?: number;
  typingSpeed?: number;
  pauseRate?: number;
}

export interface MouseFeatures {
  sampleCount?: number;
  meanVelocity?: number;
  velocityStdDev?: number;
  meanAcceleration?: number;
  directionChangeRate?: number;
  totalDistance?: number;
  movementDuration?: number;
  meanPauseTime?: number;
}

export interface ClickFeatures {
  clickCount?: number;
  doubleClickCount?: number;
  meanInterval?: number;
  intervalStdDev?: number;
  clickFrequency?: number;
}

export interface ScrollFeatures {
  scrollEventCount?: number;
  meanVelocity?: number;
  totalDistance?: number;
  meanPauseDuration?: number;
  eventRate?: number;
}

export interface DerivedFeatures {
  typing?: TypingFeatures;
  mouse?: MouseFeatures;
  click?: ClickFeatures;
  scroll?: ScrollFeatures;
}

export interface TelemetryRequest {
  session_id: string;
  features?: DerivedFeatures;
  /** Pre-flattened numeric vector, for server-side integrations. */
  flat_features?: Record<string, number>;
  network?: NetworkContext;
  source?: 'SDK' | 'SIMULATION' | 'BACKFILL';
  sample_metadata?: Record<string, unknown>;
}

export interface TelemetryResponse {
  accepted: boolean;
  features_received: number;
  /** 0-1 composite anomaly score from the fused detectors. */
  anomaly_score: number;
  trust: TrustResult;
  learned: {
    shadow_learned?: boolean;
    shadow_rejected?: boolean;
    core_observations?: number;
    shadow_observations?: number;
    promotion?: { promote: boolean; distance?: number; reasons?: string[] };
  };
  rejected_reason?: string | null;
}

// ------------------------------------------------------------------- session

export interface DeviceContext {
  fingerprint: string;
  label?: string;
  platform?: string;
  browser?: string;
  os_name?: string;
  screen?: string;
  timezone?: string;
}

export interface NetworkContext {
  country?: string;
  asn?: string;
  is_vpn?: boolean;
  is_proxy_or_tor?: boolean;
  /** Accepted for context; stored only as a SHA-256 digest. */
  client_ip?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
  mfa_code?: string;
  device: DeviceContext;
  network?: NetworkContext;
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
}

export interface LoginResponse {
  session: SessionInfo;
  /** Returned once. The server persists only its SHA-256 digest. */
  token: string;
  trust: TrustResult;
}

// ------------------------------------------------------------------- proofs

/**
 * A Trust Receipt binds a decision to its context so it can be independently
 * verified later. Implemented in Phase 2; hashing and Merkle anchoring in
 * Phase 3.
 */
export interface TrustReceipt {
  receipt_id: string;
  session_id: string;
  user_id: string;
  device_id: string;
  action: string;
  resource?: string | null;
  decision: Decision;
  tci: number;
  trust_state: TrustState;
  action_risk: number;
  nonce: string;
  issued_at: string;
  expires_at: string;
  /** SHA-256 over the canonical receipt payload, including the evidence hash. */
  receipt_hash?: string | null;
  evidence_hash?: string | null;
  merkle_root?: string | null;
  merkle_proof?: string[] | null;
  anchor?: {
    network: string;
    transaction_id?: string | null;
    anchored_at?: string | null;
    /** Only hashes and roots are ever anchored — never raw behavioral data. */
    anchored_payload: 'HASHES_ONLY';
  } | null;
}

export interface ReceiptVerification {
  valid: boolean;
  reasons: string[];
  receipt_id: string;
  verified_at: string;
  hash_matches: boolean;
  merkle_proof_valid?: boolean | null;
  expired?: boolean;
}

// ------------------------------------------------------------- configuration

export interface TrustModelInfo {
  schema_version: string;
  /** The file the backend actually loaded, so provenance is visible. */
  source: string;
  weights: Record<FactorName, number>;
  cold_start_tci: number;
  state_bands: Array<{ state: TrustState; min: number }>;
  hysteresis: {
    escalation_confirmations: number;
    decisive_drop: number;
    decisive_depth: number;
    multi_level_escalation: number;
    recovery_buffer: number;
    recovery_confirmations: number;
    no_auto_recovery_states: TrustState[];
    no_recovery_with_open_incident: boolean;
  };
  action_risk_profiles: Record<string, ActionRiskProfile>;
  evidence_types: string[];
  disclaimer: string;
}

// --------------------------------------------------------------- api helpers

/** Uniform error shape returned by the platform API. */
export interface ApiErrorBody {
  error: string;
  details?: unknown;
}

/** Platform API version prefix. */
export const API_PREFIX = '/api/v1';

/** TCI bounds. */
export const TCI_MIN = 0;
export const TCI_MAX = 100;

/**
 * The disclaimer that must accompany any user-facing TCI value.
 * Served by the API in the SOC overview and trust-model payloads.
 */
export const TCI_DISCLAIMER =
  'TCI is an engineering trust index on a 0-100 scale, not a probability. ' +
  'All weights and thresholds are configurable prototype parameters.';

/**
 * Trust-state severity ordering, for comparisons such as "did this escalate?".
 * CONTAINED ranks highest because it implies active operator intervention.
 */
export const STATE_SEVERITY: Record<TrustState, number> = {
  TRUSTED: 0,
  DEGRADED: 1,
  SUSPICIOUS: 2,
  CRITICAL: 3,
  BLOCKED: 4,
  CONTAINED: 5,
};

/** Display colours shared by the SOC dashboard and any embedded widget. */
export const STATE_COLOR: Record<TrustState, string> = {
  TRUSTED: '#22c55e',
  DEGRADED: '#eab308',
  SUSPICIOUS: '#f97316',
  CRITICAL: '#ef4444',
  BLOCKED: '#b91c1c',
  CONTAINED: '#a855f7',
};

/** Default state band floors, mirrored from trust_model.json. */
export const DEFAULT_STATE_BANDS: ReadonlyArray<{ state: TrustState; min: number }> = [
  { state: 'TRUSTED', min: 85 },
  { state: 'DEGRADED', min: 70 },
  { state: 'SUSPICIOUS', min: 50 },
  { state: 'CRITICAL', min: 30 },
  { state: 'BLOCKED', min: 0 },
];

/** Default TCI factor weights, mirrored from trust_model.json. */
export const DEFAULT_WEIGHTS: Record<FactorName, number> = {
  identity: 0.15,
  device: 0.2,
  behavior: 0.3,
  network: 0.15,
  session: 0.1,
  history: 0.1,
};

/** Action risk bands, mirrored from trust_model.json. */
export const RISK_BANDS: ReadonlyArray<{ min_risk: number; band: RiskBand }> = [
  { min_risk: 85, band: 'CRITICAL' },
  { min_risk: 60, band: 'HIGH' },
  { min_risk: 30, band: 'MEDIUM' },
  { min_risk: 0, band: 'LOW' },
];

/** Returns the band a numeric action risk falls into. */
export function riskBandFor(risk: number): RiskBand {
  for (const entry of RISK_BANDS) {
    if (risk >= entry.min_risk) return entry.band;
  }
  return 'LOW';
}

/** Returns the state band a TCI falls into, before hysteresis. */
export function stateBandFor(tci: number): TrustState {
  for (const band of DEFAULT_STATE_BANDS) {
    if (tci >= band.min) return band.state;
  }
  return 'BLOCKED';
}

/** True when the transition moved to a more severe state. */
export function isEscalation(from: TrustState, to: TrustState): boolean {
  return STATE_SEVERITY[to] > STATE_SEVERITY[from];
}

/** Clamps a value into the valid TCI range. */
export function clampTci(value: number): number {
  if (!Number.isFinite(value)) return TCI_MIN;
  return Math.min(TCI_MAX, Math.max(TCI_MIN, value));
}

/**
 * Key patterns that must never appear in an outbound telemetry payload.
 * Mirrors `ml/feature_extraction/features.py::assert_no_raw_data`.
 */
export const FORBIDDEN_TELEMETRY_KEYS: readonly string[] = [
  'character',
  'charcode',
  'keyvalue',
  'key_value',
  'keystroke',
  'keypress',
  'password',
  'secret',
  'token',
  'clipboard',
  'selection',
  'inputvalue',
  'input_value',
  'text',
  'content',
  'email',
  'phone',
  'ssn',
  'cardnumber',
];
