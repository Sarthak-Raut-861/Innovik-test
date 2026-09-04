/**
 * @trustpulse/sdk - Privacy Manager
 *
 * Implements strict privacy boundaries, sensitive element exclusion,
 * and zero-content guarantees across all behavioral collectors.
 */
import type { PrivacyMode } from "../config/types";
export declare class PrivacyManager {
    private config;
    private static readonly SENSITIVE_SELECTORS;
    private static readonly SENSITIVE_PATTERN;
    constructor(privacyMode?: PrivacyMode, ignoredSelectors?: string[], signalToggles?: {
        collectTyping: boolean;
        collectMouse: boolean;
        collectClick: boolean;
        collectScroll: boolean;
        collectTouch: boolean;
        collectDevice: boolean;
    });
    getPrivacyMode(): PrivacyMode;
    setPrivacyMode(mode: PrivacyMode): void;
    isTypingEnabled(): boolean;
    isMouseEnabled(): boolean;
    isClickEnabled(): boolean;
    isScrollEnabled(): boolean;
    isTouchEnabled(): boolean;
    isDeviceEnabled(): boolean;
    /**
     * Evaluates whether an event target is an ignored or sensitive field.
     * If true, behavioral observers must completely skip processing the event.
     */
    isElementSensitive(target: EventTarget | null): boolean;
    /**
     * Produces a sanitized, non-content structural identifier for an element.
     * NEVER extracts innerText, textContent, or input values.
     */
    getSafeElementDescriptor(target: EventTarget | null): string;
}
//# sourceMappingURL=PrivacyManager.d.ts.map