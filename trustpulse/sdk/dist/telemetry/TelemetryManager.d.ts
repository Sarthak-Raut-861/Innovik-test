/**
 * @trustpulse/sdk - Telemetry Manager
 *
 * Orchestrates periodic signal sampling, local feature extraction,
 * queue management, batch dispatch, and page lifecycle unload hooks.
 */
import type { ValidatedTrustPulseConfig } from "../config/types";
import { SessionManager } from "../session/SessionManager";
import { PrivacyManager } from "../privacy/PrivacyManager";
import { Logger } from "../utils/Logger";
import type { TelemetryPacket } from "./TelemetryTypes";
export declare class TelemetryManager {
    private config;
    private sessionManager;
    private privacyManager;
    private queue;
    private client;
    private logger;
    private typingCollector;
    private mouseCollector;
    private clickCollector;
    private scrollCollector;
    private touchCollector;
    private deviceCollector;
    private timerId;
    private lastHarvestTime;
    private isFlushing;
    private boundVisibilityChange;
    private boundPageHide;
    constructor(config: ValidatedTrustPulseConfig, sessionManager: SessionManager, privacyManager: PrivacyManager, logger: Logger);
    start(): void;
    pause(): void;
    resume(): void;
    stop(): void;
    destroy(): void;
    getPrivacyManager(): PrivacyManager;
    getQueueSize(): number;
    getDroppedCount(): number;
    /**
     * Harvests samples from collectors, computes feature vectors, creates packet,
     * enqueues it, and dispatches batches.
     */
    harvestAndDispatch(eventType?: "behavioral_batch" | "session_stop"): Promise<void>;
    /**
     * Forces an immediate flush of all queued telemetry.
     */
    flush(): Promise<void>;
    /**
     * Extracts features and builds a signed TelemetryPacket.
     */
    buildTelemetryPacket(eventType?: "behavioral_batch" | "session_start" | "session_stop" | "heartbeat"): TelemetryPacket | null;
    private flushQueue;
    private handleVisibilityChange;
    private handlePageHide;
    private flushViaBeaconOrFetch;
}
//# sourceMappingURL=TelemetryManager.d.ts.map