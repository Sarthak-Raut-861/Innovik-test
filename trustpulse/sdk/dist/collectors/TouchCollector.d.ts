/**
 * @trustpulse/sdk - Touch Dynamics Collector
 *
 * Collects touch interaction durations, swipe velocities, and gesture cadences.
 * Gracefully operates on touch-enabled devices and remains inert on desktop environments.
 */
import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
export interface TouchGestureSample {
    duration: number;
    distance: number;
    velocity: number;
    direction: "up" | "down" | "left" | "right" | "tap";
}
export declare class TouchCollector extends BaseCollector {
    private privacyManager;
    private samples;
    private touchStartTime;
    private startX;
    private startY;
    private readonly maxSamples;
    private boundTouchStart;
    private boundTouchEnd;
    constructor(privacyManager: PrivacyManager, maxSamples?: number);
    start(): void;
    stop(): void;
    clear(): void;
    getAndResetSamples(): TouchGestureSample[];
    private handleTouchStart;
    private handleTouchEnd;
}
//# sourceMappingURL=TouchCollector.d.ts.map