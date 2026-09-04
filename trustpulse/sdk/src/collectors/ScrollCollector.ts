/**
 * @trustpulse/sdk - Scroll Dynamics Collector
 *
 * Collects relative scroll movement dynamics (velocities, frequencies, pause durations).
 * Avoids recording exact page positions or content identifiers.
 */

import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
import { TimeUtils } from "../utils/Time";
import { BrowserUtils } from "../utils/Browser";

export interface ScrollSample {
  timestamp: number;
  deltaY: number;
  duration: number; // Duration of scroll burst
}

export class ScrollCollector extends BaseCollector {
  private privacyManager: PrivacyManager;
  private samples: ScrollSample[] = [];
  private lastScrollTime = 0;
  private lastScrollY = 0;
  private readonly sampleThrottleMs = 30;
  private readonly maxSamples: number;

  private boundScrollHandler: () => void;

  constructor(privacyManager: PrivacyManager, maxSamples = 100) {
    super();
    this.privacyManager = privacyManager;
    this.maxSamples = maxSamples;
    this.boundScrollHandler = this.handleScroll.bind(this);
  }

  public start(): void {
    if (this.active || !BrowserUtils.isBrowser()) return;
    this.active = true;
    this.paused = false;

    this.lastScrollY = window.scrollY || window.pageYOffset || 0;
    window.addEventListener("scroll", this.boundScrollHandler, { capture: true, passive: true });
  }

  public stop(): void {
    if (!this.active || !BrowserUtils.isBrowser()) return;
    this.active = false;
    this.paused = false;

    window.removeEventListener("scroll", this.boundScrollHandler, { capture: true });
    this.clear();
  }

  public clear(): void {
    this.samples = [];
    this.lastScrollTime = 0;
    this.lastScrollY = 0;
  }

  public getAndResetSamples(): ScrollSample[] {
    const extracted = this.samples;
    this.samples = [];
    return extracted;
  }

  private handleScroll(): void {
    if (!this.isActive() || !this.privacyManager.isScrollEnabled()) return;

    const now = TimeUtils.now();
    if (now - this.lastScrollTime < this.sampleThrottleMs) {
      return;
    }

    const currentY = window.scrollY || window.pageYOffset || 0;
    const deltaY = Math.abs(currentY - this.lastScrollY);
    const duration = this.lastScrollTime > 0 ? TimeUtils.delta(this.lastScrollTime, now) : 0;

    this.lastScrollTime = now;
    this.lastScrollY = currentY;

    if (deltaY > 0) {
      this.samples.push({
        timestamp: now,
        deltaY,
        duration,
      });

      if (this.samples.length > this.maxSamples) {
        this.samples.shift();
      }
    }
  }
}
