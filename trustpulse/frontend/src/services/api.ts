/**
 * TRUSTPULSE API client.
 *
 * All requests use RELATIVE URLs. In development Vite proxies `/api` to the
 * backend; in production the frontend container proxies it via nginx. The
 * browser never addresses the backend host directly.
 */

import type {
  ActionRiskProfile,
  DeviceSummary,
  LoginResponse,
  SessionInfo,
  SocOverview,
  SocSessionDetail,
  SocSessionSummary,
  TelemetryResponse,
  TrustHistoryPoint,
  TrustModelInfo,
  TrustResult,
  UserSummary,
} from '../types/trust';

const API = '/api/v1';

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

/**
 * The integration API key. In a real deployment this lives on the customer's
 * backend and the browser never sees it; TrustDev calls TRUSTPULSE server-side.
 * For this prototype the demo key is exposed to the browser so the whole loop
 * can be demonstrated with one command.
 */
export function getApiKey(): string {
  return import.meta.env.VITE_TRUSTPULSE_API_KEY || 'tp_demo_trustpulse_key_0001';
}

export function getTenantId(): string {
  return import.meta.env.VITE_TRUSTPULSE_TENANT || 'trustdev-demo';
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  headers.set('X-TrustPulse-API-Key', getApiKey());
  headers.set('X-TrustPulse-Tenant-Id', getTenantId());

  const response = await fetch(`${API}${path}`, { ...init, headers });
  const text = await response.text();
  const body = text ? safeJson(text) : null;

  if (!response.ok) {
    const message =
      (body && typeof body === 'object' && 'error' in body
        ? String((body as Record<string, unknown>).error)
        : null) || `Request failed (${response.status})`;
    throw new ApiError(response.status, message, body);
  }
  return body as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// ------------------------------------------------------------------ auth/session
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
  client_ip?: string;
}

export function login(payload: {
  username: string;
  password: string;
  mfa_code?: string;
  device: DeviceContext;
  network?: NetworkContext;
}): Promise<LoginResponse> {
  return request<LoginResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function endSession(sessionId: string): Promise<SessionInfo> {
  return request<SessionInfo>(`/session/${encodeURIComponent(sessionId)}/end`, {
    method: 'POST',
  });
}

export function createSession(payload: {
  user_id: string;
  device: DeviceContext;
  network?: NetworkContext;
  auth_method?: string;
  mfa_used?: boolean;
}): Promise<SessionInfo> {
  return request<SessionInfo>('/session', { method: 'POST', body: JSON.stringify(payload) });
}

// --------------------------------------------------------------------- telemetry
export function sendTelemetry(payload: {
  session_id: string;
  features?: Record<string, unknown>;
  flat_features?: Record<string, number>;
  network?: NetworkContext;
  source?: 'SDK' | 'SIMULATION' | 'BACKFILL';
  sample_metadata?: Record<string, unknown>;
}): Promise<TelemetryResponse> {
  return request<TelemetryResponse>('/telemetry', {
    method: 'POST',
    body: JSON.stringify({ source: 'SDK', ...payload }),
  });
}

// ------------------------------------------------------------------------- trust
export function getTrust(sessionId: string): Promise<TrustResult> {
  return request<TrustResult>(`/trust/${encodeURIComponent(sessionId)}`);
}

export function evaluateTrust(payload: {
  session_id: string;
  features?: Record<string, unknown>;
  network?: NetworkContext;
  trigger?: string;
}): Promise<TrustResult> {
  return request<TrustResult>('/trust/evaluate', {
    method: 'POST',
    body: JSON.stringify({ trigger: 'MANUAL', ...payload }),
  });
}

export interface TrustHistory {
  session_id: string;
  points: TrustHistoryPoint[];
  state_timeline: Array<{
    observed_at: string | null;
    from: string | null;
    to: string;
    tci: number;
    trigger: string;
  }>;
}

export function getTrustHistory(sessionId: string): Promise<TrustHistory> {
  return request<TrustHistory>(`/trust/${encodeURIComponent(sessionId)}/history`);
}

// --------------------------------------------------------------------------- SOC
export function getSocOverview(): Promise<SocOverview> {
  return request<SocOverview>('/soc/overview');
}

export function getSocSessions(limit = 50): Promise<SocSessionSummary[]> {
  return request<SocSessionSummary[]>(`/soc/sessions?limit=${limit}`);
}

export function getSocSessionDetail(sessionId: string): Promise<SocSessionDetail> {
  return request<SocSessionDetail>(`/soc/sessions/${encodeURIComponent(sessionId)}`);
}

// ------------------------------------------------------------------ transparency
export function getTrustModel(): Promise<TrustModelInfo> {
  return request<TrustModelInfo>('/config/trust-model');
}

export function getActionCatalogue(): Promise<{
  actions: Record<string, ActionRiskProfile>;
  bands: Array<{ min_risk: number; band: string }>;
  note: string;
}> {
  return request('/config/actions');
}

export function listUsers(): Promise<UserSummary[]> {
  return request<UserSummary[]>('/users');
}

export function listDevices(): Promise<DeviceSummary[]> {
  return request<DeviceSummary[]>('/devices');
}

export function getHealth(): Promise<{
  status: string;
  product: string;
  version: string;
  trust_model_version: string;
  database: string;
  redis: string;
  time: string;
}> {
  return request('/platform/health');
}
