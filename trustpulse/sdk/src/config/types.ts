/**
 * @trustpulse/sdk - Configuration Types
 *
 * Defines the public and internal configuration options for the TrustPulse SDK.
 */

export type PrivacyMode = "standard" | "strict";

export type SDKStatus = "uninitialized" | "ready" | "running" | "paused" | "stopped" | "destroyed";

export interface TrustPulseConfig {
  /**
   * The HTTPS base URL for the TrustPulse backend telemetry ingestion gateway.
   * Example: "https://api.trustpulse.security"
   */
  apiUrl: string;

  /**
   * Customer public application key (non-secret identifier).
   */
  publicKey: string;

  /**
   * The authenticated host application's session identifier.
   */
  sessionId: string;

  /**
   * Background telemetry dispatch interval in milliseconds.
   * Default: 3000ms (minimum: 1000ms, maximum: 60000ms).
   */
  telemetryIntervalMs?: number;

  /**
   * Maximum number of telemetry items buffered in memory before dropping oldest items.
   * Default: 500.
   */
  maxQueueSize?: number;

  /**
   * Number of telemetry records to bundle in a single transmission batch.
   * Default: 10.
   */
  batchSize?: number;

  /**
   * Maximum network retry attempts on transient failures.
   * Default: 3.
   */
  maxRetries?: number;

  /**
   * Enable or disable typing timing behavioral collection.
   * Default: true.
   */
  enableTypingSignals?: boolean;

  /**
   * Enable or disable mouse kinematics behavioral collection.
   * Default: true.
   */
  enableMouseSignals?: boolean;

  /**
   * Enable or disable click dynamics behavioral collection.
   * Default: true.
   */
  enableClickSignals?: boolean;

  /**
   * Enable or disable scroll dynamics behavioral collection.
   * Default: true.
   */
  enableScrollSignals?: boolean;

  /**
   * Enable or disable touch/gesture behavioral collection.
   * Default: true.
   */
  enableTouchSignals?: boolean;

  /**
   * Enable or disable non-sensitive device context collection.
   * Default: true.
   */
  enableDeviceSignals?: boolean;

  /**
   * Privacy operational mode:
   * - "standard": Aggregates features locally, discards raw input, blacklists password & sensitive fields.
   * - "strict": Enhances sanitization, suppresses element context tokens, disables high-frequency sampling.
   * Default: "standard".
   */
  privacyMode?: PrivacyMode;

  /**
   * Enable structured debug logging in browser console.
   * Default: false.
   */
  debug?: boolean;

  /**
   * Additional DOM selector queries for elements that must be strictly excluded from observation.
   */
  ignoredSelectors?: string[];
}

export interface ValidatedTrustPulseConfig extends Required<Omit<TrustPulseConfig, "ignoredSelectors">> {
  ignoredSelectors: string[];
}
