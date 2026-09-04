/**
 * @trustpulse/sdk - Time Utilities
 *
 * Provides monotonic high-resolution timing and epoch timestamps.
 * Designed to resist system clock adjustments where supported by the browser.
 */
export class TimeUtils {
    /**
     * Returns current high-resolution monotonic time in milliseconds relative to page navigation.
     */
    static now() {
        if (typeof performance !== "undefined" && typeof performance.now === "function") {
            return performance.now();
        }
        return Date.now();
    }
    /**
     * Returns standard UTC epoch timestamp in milliseconds.
     */
    static epoch() {
        return Date.now();
    }
    /**
     * Returns ISO 8601 formatted timestamp string.
     */
    static iso() {
        return new Date().toISOString();
    }
    /**
     * Calculates delta time in milliseconds with non-negative guard.
     */
    static delta(start, end) {
        const diff = end - start;
        return diff >= 0 ? diff : 0;
    }
}
//# sourceMappingURL=Time.js.map