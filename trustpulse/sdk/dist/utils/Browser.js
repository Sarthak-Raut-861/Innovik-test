/**
 * @trustpulse/sdk - Browser Utilities
 *
 * Safe browser environment detection, capability inspection, and SSR safety guards.
 */
export class BrowserUtils {
    static isBrowser() {
        return typeof window !== "undefined" && typeof document !== "undefined";
    }
    static hasTouch() {
        if (!BrowserUtils.isBrowser())
            return false;
        return ("ontouchstart" in window ||
            navigator.maxTouchPoints > 0 ||
            // @ts-expect-error msMaxTouchPoints is legacy IE/Edge
            (typeof navigator.msMaxTouchPoints === "number" && navigator.msMaxTouchPoints > 0));
    }
    static hasPointerEvents() {
        if (!BrowserUtils.isBrowser())
            return false;
        return typeof window.PointerEvent !== "undefined";
    }
    static isBeaconSupported() {
        if (!BrowserUtils.isBrowser())
            return false;
        return typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function";
    }
    static isVisibilitySupported() {
        if (!BrowserUtils.isBrowser())
            return false;
        return typeof document !== "undefined" && typeof document.visibilityState !== "undefined";
    }
    static requestIdleCallbackSafe(callback, timeout = 2000) {
        if (typeof window !== "undefined") {
            const win = window;
            if (typeof win.requestIdleCallback === "function") {
                return win.requestIdleCallback(callback, { timeout });
            }
            return window.setTimeout(callback, 50);
        }
        return 0;
    }
    static cancelIdleCallbackSafe(handle) {
        if (typeof window !== "undefined") {
            const win = window;
            if (typeof win.cancelIdleCallback === "function") {
                win.cancelIdleCallback(handle);
            }
            else {
                window.clearTimeout(handle);
            }
        }
    }
}
//# sourceMappingURL=Browser.js.map