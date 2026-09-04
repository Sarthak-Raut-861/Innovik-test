/**
 * @trustpulse/sdk - Main SDK Facade
 *
 * TrustPulse AI Continuous Session Security Client.
 *
 * ARCHITECTURAL BOUNDARY:
 * TrustPulse SDK is strictly a client-side telemetry and behavioral signal collection
 * component. The SDK NEVER calculates final security decisions, NEVER authorizes
 * transactions, NEVER accesses passwords or raw keystrokes, and NEVER overrides
 * server-side security policies. The backend is the sole security authority.
 */
import type { TrustPulseConfig, SDKStatus } from "./config/types";
export declare class TrustPulse {
    static readonly version: string;
    private readonly config;
    private readonly logger;
    private readonly sessionManager;
    private readonly privacyManager;
    private readonly telemetryManager;
    private status;
    constructor(config: TrustPulseConfig);
    /**
     * Starts behavioral telemetry collection.
     */
    start(): void;
    /**
     * Pauses signal observation and telemetry dispatch.
     */
    pause(): void;
    /**
     * Resumes signal observation and telemetry dispatch.
     */
    resume(): void;
    /**
     * Stops signal observation and tears down background timers.
     */
    stop(): void;
    /**
     * Flushes any buffered behavioral signals immediately to the backend.
     */
    flush(): Promise<void>;
    /**
     * Stops collection, clears all buffered telemetry, and unregisters event listeners.
     */
    destroy(): void;
    /**
     * Returns current operational status of the SDK.
     */
    getStatus(): SDKStatus;
    /**
     * Returns the current application session ID.
     */
    getSessionId(): string;
    /**
     * Returns the unique SDK instance identifier generated on initialization.
     */
    getSdkInstanceId(): string;
    /**
     * Updates the host application session ID upon token rotation or re-authentication.
     */
    updateSession(newSessionId: string): void;
}
//# sourceMappingURL=TrustPulse.d.ts.map