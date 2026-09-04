/**
 * @trustpulse/sdk - Browser Utilities
 *
 * Safe browser environment detection, capability inspection, and SSR safety guards.
 */
export declare class BrowserUtils {
    static isBrowser(): boolean;
    static hasTouch(): boolean;
    static hasPointerEvents(): boolean;
    static isBeaconSupported(): boolean;
    static isVisibilitySupported(): boolean;
    static requestIdleCallbackSafe(callback: () => void, timeout?: number): number;
    static cancelIdleCallbackSafe(handle: number): void;
}
//# sourceMappingURL=Browser.d.ts.map