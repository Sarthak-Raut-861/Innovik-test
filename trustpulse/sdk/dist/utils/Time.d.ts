/**
 * @trustpulse/sdk - Time Utilities
 *
 * Provides monotonic high-resolution timing and epoch timestamps.
 * Designed to resist system clock adjustments where supported by the browser.
 */
export declare class TimeUtils {
    /**
     * Returns current high-resolution monotonic time in milliseconds relative to page navigation.
     */
    static now(): number;
    /**
     * Returns standard UTC epoch timestamp in milliseconds.
     */
    static epoch(): number;
    /**
     * Returns ISO 8601 formatted timestamp string.
     */
    static iso(): string;
    /**
     * Calculates delta time in milliseconds with non-negative guard.
     */
    static delta(start: number, end: number): number;
}
//# sourceMappingURL=Time.d.ts.map