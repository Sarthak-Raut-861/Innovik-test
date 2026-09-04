/**
 * @trustpulse/sdk - Click Dynamics Collector
 *
 * Collects click timing intervals, double-click cadences, and aggregate frequency.
 * Strictly guarantees that button labels, input contents, account numbers, or
 * transaction amounts are NEVER inspected or captured.
 */
import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
export interface ClickSample {
    timestamp: number;
    intervalFromLastClick: number;
    isDoubleClick: boolean;
    elementCategory: string;
}
export declare class ClickCollector extends BaseCollector {
    private privacyManager;
    private samples;
    private lastClickTime;
    private readonly maxSamples;
    private readonly doubleClickThresholdMs;
    private boundClickHandler;
    constructor(privacyManager: PrivacyManager, maxSamples?: number);
    start(): void;
    stop(): void;
    clear(): void;
    getAndResetSamples(): ClickSample[];
    private handleClick;
}
//# sourceMappingURL=ClickCollector.d.ts.map