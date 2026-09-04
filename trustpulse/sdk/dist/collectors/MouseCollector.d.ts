/**
 * @trustpulse/sdk - Mouse Kinematics Collector
 *
 * Collects relative movement dynamics (distances, velocities, angular changes).
 * Raw coordinate streams are NEVER transmitted to the server; they are buffered
 * locally only long enough to extract aggregate statistical features.
 */
import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
export interface MousePointSample {
    x: number;
    y: number;
    timestamp: number;
}
export declare class MouseCollector extends BaseCollector {
    private privacyManager;
    private samples;
    private lastSampleTime;
    private readonly sampleThrottleMs;
    private readonly maxSamples;
    private boundMouseMove;
    constructor(privacyManager: PrivacyManager, maxSamples?: number);
    start(): void;
    stop(): void;
    clear(): void;
    getAndResetSamples(): MousePointSample[];
    private handleMouseMove;
}
//# sourceMappingURL=MouseCollector.d.ts.map