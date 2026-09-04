/**
 * @trustpulse/sdk - Mouse Kinematics Collector
 *
 * Collects relative movement dynamics (distances, velocities, angular changes).
 * Raw coordinate streams are NEVER transmitted to the server; they are buffered
 * locally only long enough to extract aggregate statistical features.
 */

import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
import { TimeUtils } from "../utils/Time";
import { BrowserUtils } from "../utils/Browser";

export interface MousePointSample {
  x: number;
  y: number;
  timestamp: number;
}

export class MouseCollector extends BaseCollector {
  private privacyManager: PrivacyManager;
  private samples: MousePointSample[] = [];
  private lastSampleTime = 0;
  private readonly sampleThrottleMs = 16; // ~60 Hz sampling cap
  private readonly maxSamples: number;

  private boundMouseMove: (e: MouseEvent) => void;

  constructor(privacyManager: PrivacyManager, maxSamples = 200) {
    super();
    this.privacyManager = privacyManager;
    this.maxSamples = maxSamples;
    this.boundMouseMove = this.handleMouseMove.bind(this);
  }

  public start(): void {
    if (this.active || !BrowserUtils.isBrowser()) return;
    this.active = true;
    this.paused = false;

    window.addEventListener("mousemove", this.boundMouseMove, { capture: true, passive: true });
  }

  public stop(): void {
    if (!this.active || !BrowserUtils.isBrowser()) return;
    this.active = false;
    this.paused = false;

    window.removeEventListener("mousemove", this.boundMouseMove, { capture: true });
    this.clear();
  }

  public clear(): void {
    this.samples = [];
    this.lastSampleTime = 0;
  }

  public getAndResetSamples(): MousePointSample[] {
    const extracted = this.samples;
    this.samples = [];
    return extracted;
  }

  private handleMouseMove(event: MouseEvent): void {
    if (!this.isActive() || !this.privacyManager.isMouseEnabled()) return;

    const now = TimeUtils.now();
    if (now - this.lastSampleTime < this.sampleThrottleMs) {
      return;
    }

    this.lastSampleTime = now;
    this.samples.push({
      x: event.clientX,
      y: event.clientY,
      timestamp: now,
    });

    if (this.samples.length > this.maxSamples) {
      this.samples.shift();
    }
  }
}
