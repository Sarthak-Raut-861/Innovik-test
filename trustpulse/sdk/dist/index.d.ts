/**
 * @trustpulse/sdk - Continuous Session Security Web Telemetry SDK
 *
 * Copyright (c) 2026 TrustPulse AI. Licensed under the Apache License, Version 2.0.
 */
import { TrustPulse } from "./TrustPulse";
export { TrustPulse };
export default TrustPulse;
export type { TrustPulseConfig, ValidatedTrustPulseConfig, SDKStatus, PrivacyMode } from "./config/types";
export type { SessionContext, SessionLifecycleState } from "./session/SessionTypes";
export type { TypingFeatures, MouseFeatures, ClickFeatures, ScrollFeatures, TouchFeatures, DeviceFeatures, ExtractedFeaturePayload, } from "./features/FeatureTypes";
export { FEATURE_SCHEMA_VERSION } from "./features/FeatureTypes";
export type { TelemetryPacket, TelemetryBatch, TelemetryPacketMetadata } from "./telemetry/TelemetryTypes";
export { TELEMETRY_SCHEMA_VERSION, SDK_VERSION } from "./telemetry/TelemetryTypes";
export type { TransportResponse, ITelemetryClient } from "./transport/TransportTypes";
export { BaseSDKError, ConfigurationError, SDKInitializationError, SessionBindingError, TelemetryValidationError, TransportError, PrivacyConfigurationError, } from "./errors/SDKError";
//# sourceMappingURL=index.d.ts.map