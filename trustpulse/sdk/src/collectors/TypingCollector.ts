/**
 * @trustpulse/sdk - Privacy-Preserving Typing Collector
 *
 * Collects keypress timing dynamics (dwell times and flight times) strictly.
 * ZERO character values, key codes, text strings, or form values are ever accessed.
 * Sensitive fields (passwords, OTPs, PINs, card numbers, ignored fields) are completely excluded.
 */

import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
import { TimeUtils } from "../utils/Time";
import { BrowserUtils } from "../utils/Browser";

export interface KeystrokeTimingSample {
  dwellTime: number;   // Duration key was held down (ms)
  flightTime: number;  // Duration from previous key release to current key press (ms)
}

export class TypingCollector extends BaseCollector {
  private privacyManager: PrivacyManager;
  private keydownTime: number | null = null;
  private lastKeyupTime: number | null = null;
  private samples: KeystrokeTimingSample[] = [];
  private readonly maxSamples: number;

  // Bound event handlers for clean registration and deregistration
  private boundKeyDown: (e: KeyboardEvent) => void;
  private boundKeyUp: (e: KeyboardEvent) => void;

  constructor(privacyManager: PrivacyManager, maxSamples = 100) {
    super();
    this.privacyManager = privacyManager;
    this.maxSamples = maxSamples;

    this.boundKeyDown = this.handleKeyDown.bind(this);
    this.boundKeyUp = this.handleKeyUp.bind(this);
  }

  public start(): void {
    if (this.active || !BrowserUtils.isBrowser()) return;
    this.active = true;
    this.paused = false;

    window.addEventListener("keydown", this.boundKeyDown, { capture: true, passive: true });
    window.addEventListener("keyup", this.boundKeyUp, { capture: true, passive: true });
  }

  public stop(): void {
    if (!this.active || !BrowserUtils.isBrowser()) return;
    this.active = false;
    this.paused = false;

    window.removeEventListener("keydown", this.boundKeyDown, { capture: true });
    window.removeEventListener("keyup", this.boundKeyUp, { capture: true });
    this.clear();
  }

  public clear(): void {
    this.samples = [];
    this.keydownTime = null;
    this.lastKeyupTime = null;
  }

  public getAndResetSamples(): KeystrokeTimingSample[] {
    const extracted = this.samples;
    this.samples = [];
    return extracted;
  }

  private handleKeyDown(event: KeyboardEvent): void {
    if (!this.isActive() || !this.privacyManager.isTypingEnabled()) return;

    // Strict Privacy Gate: Do not record any timing if the element is sensitive
    if (this.privacyManager.isElementSensitive(event.target)) {
      this.keydownTime = null;
      this.lastKeyupTime = null;
      return;
    }

    // Capture ONLY monotonic high-resolution timestamp
    // NEVER read event.key, event.code, event.keyCode, or event.target.value
    const now = TimeUtils.now();
    this.keydownTime = now;
  }

  private handleKeyUp(event: KeyboardEvent): void {
    if (!this.isActive() || !this.privacyManager.isTypingEnabled()) return;

    // Strict Privacy Gate
    if (this.privacyManager.isElementSensitive(event.target)) {
      this.keydownTime = null;
      this.lastKeyupTime = null;
      return;
    }

    if (this.keydownTime === null) return;

    const now = TimeUtils.now();
    const dwellTime = TimeUtils.delta(this.keydownTime, now);

    // Calculate flight time from previous keyup if available
    let flightTime = 0;
    if (this.lastKeyupTime !== null) {
      flightTime = TimeUtils.delta(this.lastKeyupTime, this.keydownTime);
    }

    this.lastKeyupTime = now;
    this.keydownTime = null;

    // Filter out aberrant timing anomalies (> 5000ms is a pause, not a stroke)
    if (dwellTime <= 3000) {
      this.samples.push({
        dwellTime,
        flightTime: flightTime <= 5000 ? flightTime : 0,
      });

      // Bounded buffer to prevent memory leaks
      if (this.samples.length > this.maxSamples) {
        this.samples.shift();
      }
    }
  }
}
