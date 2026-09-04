/**
 * @trustpulse/sdk - Configuration Validator
 *
 * Enforces strict validation of all initialization parameters.
 * Rejects insecure or missing values immediately upon initialization.
 */
import { ConfigurationError } from "../errors/SDKError";
export function validateConfig(config) {
    if (!config || typeof config !== "object") {
        throw new ConfigurationError("Configuration object must be provided.");
    }
    // Validate apiUrl
    if (!config.apiUrl || typeof config.apiUrl !== "string" || config.apiUrl.trim() === "") {
        throw new ConfigurationError("apiUrl is required and must be a non-empty string.");
    }
    let parsedUrl;
    try {
        parsedUrl = new URL(config.apiUrl);
    }
    catch {
        throw new ConfigurationError(`Invalid apiUrl format: "${config.apiUrl}". Must be a valid URL.`);
    }
    const isLocalhost = parsedUrl.hostname === "localhost" || parsedUrl.hostname === "127.0.0.1";
    if (parsedUrl.protocol !== "https:" && !isLocalhost) {
        throw new ConfigurationError("apiUrl must use HTTPS protocol in production environments.");
    }
    // Validate publicKey
    if (!config.publicKey || typeof config.publicKey !== "string" || config.publicKey.trim() === "") {
        throw new ConfigurationError("publicKey is required and must be a non-empty string.");
    }
    // Validate sessionId
    if (!config.sessionId || typeof config.sessionId !== "string" || config.sessionId.trim() === "") {
        throw new ConfigurationError("sessionId is required and must be a non-empty string.");
    }
    // Validate telemetryIntervalMs
    const interval = config.telemetryIntervalMs ?? 3000;
    if (typeof interval !== "number" || Number.isNaN(interval) || interval < 1000 || interval > 60000) {
        throw new ConfigurationError("telemetryIntervalMs must be a number between 1000 and 60000 ms.");
    }
    // Validate maxQueueSize
    const maxQueue = config.maxQueueSize ?? 500;
    if (typeof maxQueue !== "number" || Number.isNaN(maxQueue) || maxQueue < 10 || maxQueue > 5000) {
        throw new ConfigurationError("maxQueueSize must be an integer between 10 and 5000.");
    }
    // Validate batchSize
    const batch = config.batchSize ?? 10;
    if (typeof batch !== "number" || Number.isNaN(batch) || batch < 1 || batch > 100) {
        throw new ConfigurationError("batchSize must be an integer between 1 and 100.");
    }
    // Validate maxRetries
    const retries = config.maxRetries ?? 3;
    if (typeof retries !== "number" || Number.isNaN(retries) || retries < 0 || retries > 10) {
        throw new ConfigurationError("maxRetries must be an integer between 0 and 10.");
    }
    // Validate privacyMode
    const privacyMode = config.privacyMode ?? "standard";
    if (privacyMode !== "standard" && privacyMode !== "strict") {
        throw new ConfigurationError(`Invalid privacyMode "${privacyMode}". Expected "standard" | "strict".`);
    }
    // Validate ignoredSelectors
    const ignoredSelectors = Array.isArray(config.ignoredSelectors)
        ? config.ignoredSelectors.filter((s) => typeof s === "string" && s.trim().length > 0)
        : [];
    return {
        apiUrl: config.apiUrl.replace(/\/+$/, ""),
        publicKey: config.publicKey.trim(),
        sessionId: config.sessionId.trim(),
        telemetryIntervalMs: interval,
        maxQueueSize: maxQueue,
        batchSize: batch,
        maxRetries: retries,
        enableTypingSignals: config.enableTypingSignals ?? true,
        enableMouseSignals: config.enableMouseSignals ?? true,
        enableClickSignals: config.enableClickSignals ?? true,
        enableScrollSignals: config.enableScrollSignals ?? true,
        enableTouchSignals: config.enableTouchSignals ?? true,
        enableDeviceSignals: config.enableDeviceSignals ?? true,
        privacyMode,
        debug: config.debug ?? false,
        ignoredSelectors,
    };
}
//# sourceMappingURL=validator.js.map