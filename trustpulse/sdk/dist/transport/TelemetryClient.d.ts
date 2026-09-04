/**
 * @trustpulse/sdk - Telemetry Transport Client
 *
 * Dispatches telemetry batches to the TrustPulse ingestion endpoint over HTTPS.
 * Employs automatic bounded retries on transient errors and supports beacon dispatch on page teardown.
 */
import type { TelemetryBatch } from "../telemetry/TelemetryTypes";
import type { ITelemetryClient, TransportResponse } from "./TransportTypes";
import { Logger } from "../utils/Logger";
export declare class TelemetryClient implements ITelemetryClient {
    private readonly endpoint;
    private readonly publicKey;
    private sessionId;
    private readonly maxRetries;
    private readonly retryManager;
    private readonly logger;
    constructor(apiUrl: string, publicKey: string, sessionId: string, maxRetries?: number, logger?: Logger);
    updateSessionId(sessionId: string): void;
    sendBatch(batch: TelemetryBatch): Promise<TransportResponse>;
    sendBeacon(batch: TelemetryBatch): boolean;
}
//# sourceMappingURL=TelemetryClient.d.ts.map