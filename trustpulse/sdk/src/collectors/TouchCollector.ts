/**
 * @trustpulse/sdk - Touch Dynamics Collector
 *
 * Collects touch interaction durations, swipe velocities, and gesture cadences.
 * Gracefully operates on touch-enabled devices and remains inert on desktop environments.
 */

import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
import { TimeUtils } from "../utils/Time";
import { MathUtils } from "../utils/Math";
import { BrowserUtils } from "../utils/Browser";

export interface TouchGestureSample {
  duration: number;
  distance: number;
  velocity: number;
  direction: "up" | "down" | "left" | "right" | "tap";
}

export class TouchCollector extends BaseCollector {
  private privacyManager: PrivacyManager;
  private samples: TouchGestureSample[] = [];
  private touchStartTime = 0;
  private startX = 0;
  private startY = 0;
  private readonly maxSamples: number;

  private boundTouchStart: (e: TouchEvent) => void;
  private boundTouchEnd: (e: TouchEvent) => void;

  constructor(privacyManager: PrivacyManager, maxSamples = 50) {
    super();
    this.privacyManager = privacyManager;
    this.maxSamples = maxSamples;

    this.boundTouchStart = this.handleTouchStart.bind(this);
    this.boundTouchEnd = this.handleTouchEnd.bind(this);
  }

  public start(): void {
    if (this.active || !BrowserUtils.isBrowser() || !BrowserUtils.hasTouch()) return;
    this.active = true;
    this.paused = false;

    window.addEventListener("touchstart", this.boundTouchStart, { capture: true, passive: true });
    window.addEventListener("touchend", this.boundTouchEnd, { capture: true, passive: true });
  }

  public stop(): void {
    if (!this.active || !BrowserUtils.isBrowser()) return;
    this.active = false;
    this.paused = false;

    window.removeEventListener("touchstart", this.boundTouchStart, { capture: true });
    window.removeEventListener("touchend", this.boundTouchEnd, { capture: true });
    this.clear();
  }

  public clear(): void {
    this.samples = [];
    this.touchStartTime = 0;
    this.startX = 0;
    this.startY = 0;
  }

  public getAndResetSamples(): TouchGestureSample[] {
    const extracted = this.samples;
    this.samples = [];
    return extracted;
  }

  private handleTouchStart(event: TouchEvent): void {
    if (!this.isActive() || !this.privacyManager.isTouchEnabled()) return;
    if (this.privacyManager.isElementSensitive(event.target)) return;

    const touch = event.touches[0];
    if (!touch) return;

    this.touchStartTime = TimeUtils.now();
    this.startX = touch.clientX;
    this.startY = touch.clientY;
  }

  private handleTouchEnd(event: TouchEvent): void {
    if (!this.isActive() || !this.privacyManager.isTouchEnabled() || this.touchStartTime === 0) return;

    const now = TimeUtils.now();
    const duration = TimeUtils.delta(this.touchStartTime, now);
    this.touchStartTime = 0;

    const touch = event.changedTouches[0];
    if (!touch) return;

    const dx = touch.clientX - this.startX;
    const dy = touch.clientY - this.startY;
    const distance = MathUtils.euclideanDistance(this.startX, this.startY, touch.clientX, touch.clientY);
    const velocity = duration > 0 ? (distance / duration) * 1000 : 0; // px/sec

    let direction: "up" | "down" | "left" | "right" | "tap" = "tap";
    if (distance > 20) {
      if (Math.abs(dx) > Math.abs(dy)) {
        direction = dx > 0 ? "right" : "left";
      } else {
        direction = dy > 0 ? "down" : "up";
      }
    }

    this.samples.push({
      duration,
      distance: MathUtils.safeNumber(distance),
      velocity: MathUtils.safeNumber(velocity),
      direction,
    });

    if (this.samples.length > this.maxSamples) {
      this.samples.shift();
    }
  }
}
