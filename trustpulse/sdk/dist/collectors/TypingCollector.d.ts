/**
 * @trustpulse/sdk - Privacy-Preserving Typing Collector
 *
 * Collects keypress timing dynamics (dwell times and flight times) strictly.
 * ZERO character values, key codes, text strings, or form values are ever accessed.
 * Sensitive fields (passwords, OTPs, PINs, card numbers, ignored fields) are completely excluded.
 */
import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
export interface KeystrokeTimingSample {
    dwellTime: number;
    flightTime: number;
}
export declare class TypingCollector extends BaseCollector {
    private privacyManager;
    private keydownTime;
    private lastKeyupTime;
    private samples;
    private readonly maxSamples;
    private boundKeyDown;
    private boundKeyUp;
    constructor(privacyManager: PrivacyManager, maxSamples?: number);
    start(): void;
    stop(): void;
    clear(): void;
    getAndResetSamples(): KeystrokeTimingSample[];
    private handleKeyDown;
    private handleKeyUp;
}
//# sourceMappingURL=TypingCollector.d.ts.map