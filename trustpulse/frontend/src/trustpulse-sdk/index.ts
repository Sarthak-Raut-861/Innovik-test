/**
 * TRUSTPULSE Web SDK — public surface.
 *
 * Design rules:
 *  - derived features only; typed characters are never captured
 *  - the SDK never scores trust and never authorizes anything
 *  - collection is passive and bounded so it cannot degrade the host app
 */

export { TrustPulseClient } from './client';
export type { TrustPulseClientOptions, SessionBinding } from './client';
export {
  ClickCollector,
  MouseCollector,
  ScrollCollector,
  TypingCollector,
  mean,
  stdDev,
} from './collectors';
export type {
  ClickStats,
  DerivedFeatures,
  MouseStats,
  ScrollStats,
  TypingStats,
} from './collectors';
export {
  FORBIDDEN_KEY_PATTERNS,
  PrivacyViolationError,
  assertPrivacySafe,
  deviceFingerprint,
  sanitizeFeatures,
} from './privacy';
