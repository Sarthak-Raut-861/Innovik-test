/**
 * @trustpulse/sdk - Click Dynamics Collector
 *
 * Collects click timing intervals, double-click cadences, and aggregate frequency.
 * Strictly guarantees that button labels, input contents, account numbers, or
 * transaction amounts are NEVER inspected or captured.
 */

import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
import { TimeUtils } from "../utils/Time";
import { BrowserUtils } from "../utils/Browser";

export interface ClickSample {
  timestamp: number;
  intervalFromLastClick: number;
  isDoubleClick: boolean;
  elementCategory: string; // Sanitized non-content descriptor e.g. "button" or "a"
}

export class ClickCollector extends BaseCollector {
  private privacyManager: PrivacyManager;
  private samples: ClickSample[] = [];
  private lastClickTime: number | null = null;
  private readonly maxSamples: number;
  private readonly doubleClickThresholdMs = 350;

  private boundClickHandler: (e: MouseEvent) => void;

  constructor(privacyManager: PrivacyManager, maxSamples = 100) {
    super();
    this.privacyManager = privacyManager;
    this.maxSamples = maxSamples;
    this.boundClickHandler = this.handleClick.bind(this);
  }

  public start(): void {
    if (this.active || !BrowserUtils.isBrowser()) return;
    this.active = true;
    this.paused = false;

    window.addEventListener("click", this.boundClickHandler, { capture: true, passive: true });
  }

  public stop(): void {
    if (!this.active || !BrowserUtils.isBrowser()) return;
    this.active = false;
    this.paused = false;

    window.removeEventListener("click", this.boundClickHandler, { capture: true });
    this.clear();
  }

  public clear(): void {
    this.samples = [];
    this.lastClickTime = null;
  }

  public getAndResetSamples(): ClickSample[] {
    const extracted = this.samples;
    this.samples = [];
    return extracted;
  }

  private handleClick(event: MouseEvent): void {
    if (!this.isActive() || !this.privacyManager.isClickEnabled()) return;

    const now = TimeUtils.now();
    let interval = 0;
    let isDoubleClick = false;

    if (this.lastClickTime !== null) {
      interval = TimeUtils.delta(this.lastClickTime, now);
      if (interval < this.doubleClickThresholdMs) {
        isDoubleClick = true;
      }
    }

    this.lastClickTime = now;

    // Extract ONLY sanitized structural descriptor (no text, no value, no personal data)
    const elementCategory = this.privacyManager.getSafeElementDescriptor(event.target);

    this.samples.push({
      timestamp: now,
      intervalFromLastClick: interval,
      isDoubleClick,
      elementCategory,
    });

    if (this.samples.length > this.maxSamples) {
      this.samples.shift();
    }
  }
}
