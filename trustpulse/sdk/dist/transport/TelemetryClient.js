/**
 * @trustpulse/sdk - Telemetry Transport Client
 *
 * Dispatches telemetry batches to the TrustPulse ingestion endpoint over HTTPS.
 * Employs automatic bounded retries on transient errors and supports beacon dispatch on page teardown.
 */
import { RetryManager } from "./RetryManager";
import { Logger } from "../utils/Logger";
import { BrowserUtils } from "../utils/Browser";
import { SDK_VERSION } from "../telemetry/TelemetryTypes";
export class TelemetryClient {
    endpoint;
    publicKey;
    sessionId;
    maxRetries;
    retryManager;
    logger;
    constructor(apiUrl, publicKey, sessionId, maxRetries = 3, logger) {
        this.endpoint = `${apiUrl.replace(/\/+$/, "")}/v1/telemetry`;
        this.publicKey = publicKey;
        this.sessionId = sessionId;
        this.maxRetries = maxRetries;
        this.retryManager = new RetryManager();
        this.logger = logger ?? new Logger(false);
    }
    updateSessionId(sessionId) {
        this.sessionId = sessionId;
    }
    async sendBatch(batch) {
        const payload = JSON.stringify(batch);
        let attempt = 0;
        while (attempt <= this.maxRetries) {
            try {
                this.logger.debug(`Dispatching batch ${batch.batchId} (attempt ${attempt + 1}/${this.maxRetries + 1})`);
                const response = await fetch(this.endpoint, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-TrustPulse-Public-Key": this.publicKey,
                        "X-TrustPulse-Session-Id": this.sessionId,
                        "X-TrustPulse-SDK-Version": SDK_VERSION,
                    },
                    body: payload,
                    // keepalive allows request to survive page unload if supported
                    keepalive: true,
                });
                if (response.ok) {
                    this.logger.debug(`Batch ${batch.batchId} successfully delivered (status: ${response.status})`);
                    return {
                        success: true,
                        status: response.status,
                        retryable: false,
                    };
                }
                const isRetryable = response.status === 429 || response.status >= 500;
                this.logger.warn(`Batch ${batch.batchId} delivery failed with HTTP ${response.status}. Retryable: ${isRetryable}`);
                if (!isRetryable || attempt >= this.maxRetries) {
                    return {
                        success: false,
                        status: response.status,
                        message: `HTTP ${response.status}`,
                        retryable: false,
                    };
                }
            }
            catch (err) {
                this.logger.warn(`Network error transmitting batch ${batch.batchId}: ${err instanceof Error ? err.message : String(err)}`);
                if (attempt >= this.maxRetries) {
                    return {
                        success: false,
                        status: 0,
                        message: err instanceof Error ? err.message : "Network error",
                        retryable: false,
                    };
                }
            }
            attempt += 1;
            await this.retryManager.delay(attempt);
        }
        return {
            success: false,
            status: 0,
            message: "Max retries exceeded",
            retryable: false,
        };
    }
    sendBeacon(batch) {
        if (!BrowserUtils.isBeaconSupported()) {
            return false;
        }
        try {
            const payload = JSON.stringify(batch);
            const blob = new Blob([payload], { type: "application/json" });
            const sent = navigator.sendBeacon(this.endpoint, blob);
            this.logger.debug(`Beacon dispatch for batch ${batch.batchId}: ${sent ? "enqueued" : "rejected"}`);
            return sent;
        }
        catch {
            return false;
        }
    }
}
//# sourceMappingURL=TelemetryClient.js.map