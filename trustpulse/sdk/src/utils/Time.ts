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
  public static now(): number {
    if (typeof performance !== "undefined" && typeof performance.now === "function") {
      return performance.now();
    }
    return Date.now();
  }

  /**
   * Returns standard UTC epoch timestamp in milliseconds.
   */
  public static epoch(): number {
    return Date.now();
  }

  /**
   * Returns ISO 8601 formatted timestamp string.
   */
  public static iso(): string {
    return new Date().toISOString();
  }

  /**
   * Calculates delta time in milliseconds with non-negative guard.
   */
  public static delta(start: number, end: number): number {
    const diff = end - start;
    return diff >= 0 ? diff : 0;
  }
}
