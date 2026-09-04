/**
 * @trustpulse/sdk - Continuous Session Security Web Telemetry SDK
 *
 * Copyright (c) 2026 TrustPulse AI. Licensed under the Apache License, Version 2.0.
 */
import { TrustPulse } from "./TrustPulse";
export { TrustPulse };
export default TrustPulse;
export { FEATURE_SCHEMA_VERSION } from "./features/FeatureTypes";
export { TELEMETRY_SCHEMA_VERSION, SDK_VERSION } from "./telemetry/TelemetryTypes";
// Errors
export { BaseSDKError, ConfigurationError, SDKInitializationError, SessionBindingError, TelemetryValidationError, TransportError, PrivacyConfigurationError, } from "./errors/SDKError";
//# sourceMappingURL=index.js.map