/**
 * @trustpulse/sdk - Scroll Dynamics Collector
 *
 * Collects relative scroll movement dynamics (velocities, frequencies, pause durations).
 * Avoids recording exact page positions or content identifiers.
 */
import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
export interface ScrollSample {
    timestamp: number;
    deltaY: number;
    duration: number;
}
export declare class ScrollCollector extends BaseCollector {
    private privacyManager;
    private samples;
    private lastScrollTime;
    private lastScrollY;
    private readonly sampleThrottleMs;
    private readonly maxSamples;
    private boundScrollHandler;
    constructor(privacyManager: PrivacyManager, maxSamples?: number);
    start(): void;
    stop(): void;
    clear(): void;
    getAndResetSamples(): ScrollSample[];
    private handleScroll;
}
//# sourceMappingURL=ScrollCollector.d.ts.map