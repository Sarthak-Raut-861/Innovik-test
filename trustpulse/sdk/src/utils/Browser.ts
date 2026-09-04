/**
 * @trustpulse/sdk - Browser Utilities
 *
 * Safe browser environment detection, capability inspection, and SSR safety guards.
 */

export class BrowserUtils {
  public static isBrowser(): boolean {
    return typeof window !== "undefined" && typeof document !== "undefined";
  }

  public static hasTouch(): boolean {
    if (!BrowserUtils.isBrowser()) return false;
    return (
      "ontouchstart" in window ||
      navigator.maxTouchPoints > 0 ||
      // @ts-expect-error msMaxTouchPoints is legacy IE/Edge
      (typeof navigator.msMaxTouchPoints === "number" && navigator.msMaxTouchPoints > 0)
    );
  }

  public static hasPointerEvents(): boolean {
    if (!BrowserUtils.isBrowser()) return false;
    return typeof window.PointerEvent !== "undefined";
  }

  public static isBeaconSupported(): boolean {
    if (!BrowserUtils.isBrowser()) return false;
    return typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function";
  }

  public static isVisibilitySupported(): boolean {
    if (!BrowserUtils.isBrowser()) return false;
    return typeof document !== "undefined" && typeof document.visibilityState !== "undefined";
  }

  public static requestIdleCallbackSafe(callback: () => void, timeout = 2000): number {
    if (typeof window !== "undefined") {
      const win = window as unknown as { requestIdleCallback?: (cb: () => void, opt: { timeout: number }) => number };
      if (typeof win.requestIdleCallback === "function") {
        return win.requestIdleCallback(callback, { timeout });
      }
      return window.setTimeout(callback, 50);
    }
    return 0;
  }

  public static cancelIdleCallbackSafe(handle: number): void {
    if (typeof window !== "undefined") {
      const win = window as unknown as { cancelIdleCallback?: (h: number) => void };
      if (typeof win.cancelIdleCallback === "function") {
        win.cancelIdleCallback(handle);
      } else {
        window.clearTimeout(handle);
      }
    }
  }
}
