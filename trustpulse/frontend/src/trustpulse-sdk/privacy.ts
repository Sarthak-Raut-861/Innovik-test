/**
 * TRUSTPULSE SDK — privacy enforcement.
 *
 * These rules run in the browser BEFORE anything is queued for transport:
 *
 *  1. Typed characters are never captured. The typing collector records only
 *     timing deltas; `event.key` is never read.
 *  2. Only derived aggregates leave the page (means, standard deviations, rates).
 *  3. Element text, input values, selections and clipboard content are never read.
 *  4. Raw coordinates are held in memory only, bounded, and never persisted.
 *
 * The backend re-validates all of this server-side — see
 * `ml/feature_extraction/features.py::assert_no_raw_data`.
 */

/** Keys that must never appear in an outbound telemetry payload. */
export const FORBIDDEN_KEY_PATTERNS: readonly string[] = [
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

export class PrivacyViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PrivacyViolationError';
  }
}

/** Recursively rejects any payload that appears to carry raw data. */
export function assertPrivacySafe(payload: unknown, depth = 0): void {
  if (depth > 6) return;
  if (Array.isArray(payload)) {
    payload.forEach((item) => assertPrivacySafe(item, depth + 1));
    return;
  }
  if (payload && typeof payload === 'object') {
    for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
      const lowered = key.toLowerCase();
      for (const pattern of FORBIDDEN_KEY_PATTERNS) {
        if (lowered.includes(pattern)) {
          throw new PrivacyViolationError(
            `TRUSTPULSE SDK refused to collect '${key}': raw data is never transmitted`,
          );
        }
      }
      if (typeof value === 'string' && value.length > 0 && !isIdentifierLike(value)) {
        throw new PrivacyViolationError(
          `TRUSTPULSE SDK refused to collect a text value for '${key}'`,
        );
      }
      assertPrivacySafe(value, depth + 1);
    }
  }
}

/** Short identifier-like strings (device ids, schema versions) are allowed. */
function isIdentifierLike(value: string): boolean {
  return /^[A-Za-z0-9._:+/=-]{1,64}$/.test(value);
}

/** Bounds a ring buffer so memory cannot grow without limit. */
export function pushBounded<T>(buffer: T[], value: T, max: number): void {
  buffer.push(value);
  if (buffer.length > max) buffer.splice(0, buffer.length - max);
}

/** Strips anything non-numeric out of a feature object before transport. */
export function sanitizeFeatures(features: object): Record<string, unknown> {
  assertPrivacySafe(features);
  const out: Record<string, unknown> = {};
  for (const [group, value] of Object.entries(features)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const cleaned: Record<string, number> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (typeof v === 'number' && Number.isFinite(v)) cleaned[k] = v;
      }
      if (Object.keys(cleaned).length > 0) out[group] = cleaned;
    }
  }
  return out;
}

/** Non-reversible device fingerprint from public, non-identifying hints. */
export function deviceFingerprint(): {
  fingerprint: string;
  platform?: string;
  browser?: string;
  os_name?: string;
  screen?: string;
  timezone?: string;
} {
  const nav = typeof navigator !== 'undefined' ? navigator : undefined;
  const screen = typeof window !== 'undefined' ? window.screen : undefined;
  const platform = nav?.platform ?? 'unknown';
  const browser = detectBrowser(nav?.userAgent ?? '');
  const screenLabel = screen ? `${screen.width}x${screen.height}` : 'unknown';
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone ?? 'UTC';
  const osName = detectOs(nav?.userAgent ?? '');

  const basis = [platform, browser, screenLabel, timezone, osName, nav?.language ?? 'en'].join('|');
  return {
    fingerprint: `dev-${hashString(basis).toString(16).padStart(8, '0')}-${hashString(
      basis.split('').reverse().join(''),
    )
      .toString(16)
      .padStart(8, '0')}`,
    platform,
    browser,
    os_name: osName,
    screen: screenLabel,
    timezone,
  };
}

function detectBrowser(userAgent: string): string {
  if (/Edg\//.test(userAgent)) return 'Edge';
  if (/OPR\//.test(userAgent)) return 'Opera';
  if (/Firefox\//.test(userAgent)) return 'Firefox';
  if (/Chrome\//.test(userAgent)) return 'Chrome';
  if (/Safari\//.test(userAgent)) return 'Safari';
  return 'Unknown';
}

function detectOs(userAgent: string): string {
  if (/Windows/.test(userAgent)) return 'Windows';
  if (/Mac OS X/.test(userAgent)) return 'macOS';
  if (/Android/.test(userAgent)) return 'Android';
  if (/iPhone|iPad/.test(userAgent)) return 'iOS';
  if (/Linux/.test(userAgent)) return 'Linux';
  return 'Unknown';
}

/** FNV-1a 32-bit — matches the backend checksum helper. */
export function hashString(input: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}
