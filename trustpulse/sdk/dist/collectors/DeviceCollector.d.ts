/**
 * @trustpulse/sdk - Non-Sensitive Device Context Collector
 *
 * Collects technical context (platform, display properties, capability indicators).
 * In accordance with Core Rule 3 ("Behavior is evidence, not identity"), this does
 * NOT claim to create a unique identifier or deterministic device fingerprint.
 */
import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
export interface DeviceContext {
    userAgentSummary: {
        browser: string;
        os: string;
    };
    screen: {
        width: number;
        height: number;
        colorDepth: number;
        pixelRatio: number;
    };
    environment: {
        timezoneOffset: number;
        timezone?: string;
        language: string;
        languages: string[];
        touchSupport: boolean;
        maxTouchPoints: number;
        hardwareConcurrency?: number;
    };
}
export declare class DeviceCollector extends BaseCollector {
    private privacyManager;
    private cachedContext;
    constructor(privacyManager: PrivacyManager);
    start(): void;
    stop(): void;
    clear(): void;
    refresh(): DeviceContext | null;
    getContext(): DeviceContext | null;
    private parseUserAgent;
}
//# sourceMappingURL=DeviceCollector.d.ts.map