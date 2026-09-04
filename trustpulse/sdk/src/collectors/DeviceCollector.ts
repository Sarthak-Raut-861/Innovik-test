/**
 * @trustpulse/sdk - Non-Sensitive Device Context Collector
 *
 * Collects technical context (platform, display properties, capability indicators).
 * In accordance with Core Rule 3 ("Behavior is evidence, not identity"), this does
 * NOT claim to create a unique identifier or deterministic device fingerprint.
 */

import { BaseCollector } from "./BaseCollector";
import { PrivacyManager } from "../privacy/PrivacyManager";
import { BrowserUtils } from "../utils/Browser";

export interface DeviceContext {
  userAgentSummary: {
    browser: string;
    os: string;
  };
  screen: {
    width: number;
    height: number;
    colorDepth: number;
    pixelRatio: number;
  };
  environment: {
    timezoneOffset: number;
    timezone?: string;
    language: string;
    languages: string[];
    touchSupport: boolean;
    maxTouchPoints: number;
    hardwareConcurrency?: number;
  };
}

export class DeviceCollector extends BaseCollector {
  private privacyManager: PrivacyManager;
  private cachedContext: DeviceContext | null = null;

  constructor(privacyManager: PrivacyManager) {
    super();
    this.privacyManager = privacyManager;
  }

  public start(): void {
    if (this.active) return;
    this.active = true;
    this.paused = false;
    this.refresh();
  }

  public stop(): void {
    this.active = false;
    this.paused = false;
  }

  public clear(): void {
    this.cachedContext = null;
  }

  public refresh(): DeviceContext | null {
    if (!BrowserUtils.isBrowser() || !this.privacyManager.isDeviceEnabled()) {
      return null;
    }

    const nav = navigator;
    const scr = window.screen;

    let tz: string | undefined;
    try {
      tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch {
      // Fallback
    }

    this.cachedContext = {
      userAgentSummary: this.parseUserAgent(nav.userAgent || ""),
      screen: {
        width: scr ? scr.width : 0,
        height: scr ? scr.height : 0,
        colorDepth: scr ? scr.colorDepth : 0,
        pixelRatio: window.devicePixelRatio || 1,
      },
      environment: {
        timezoneOffset: new Date().getTimezoneOffset(),
        timezone: tz,
        language: nav.language || "unknown",
        languages: Array.isArray(nav.languages) ? [...nav.languages] : [nav.language || "unknown"],
        touchSupport: BrowserUtils.hasTouch(),
        maxTouchPoints: nav.maxTouchPoints || 0,
        hardwareConcurrency: nav.hardwareConcurrency || undefined,
      },
    };

    return this.cachedContext;
  }

  public getContext(): DeviceContext | null {
    if (!this.cachedContext) {
      return this.refresh();
    }
    return this.cachedContext;
  }

  private parseUserAgent(ua: string): { browser: string; os: string } {
    let browser = "Other";
    let os = "Other";

    if (/Windows/i.test(ua)) os = "Windows";
    else if (/Macintosh|Mac OS/i.test(ua)) os = "macOS";
    else if (/Android/i.test(ua)) os = "Android";
    else if (/iPhone|iPad|iPod/i.test(ua)) os = "iOS";
    else if (/Linux/i.test(ua)) os = "Linux";

    if (/Edg\//i.test(ua)) browser = "Edge";
    else if (/Chrome\//i.test(ua) && !/Chromium|Edg/i.test(ua)) browser = "Chrome";
    else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) browser = "Safari";
    else if (/Firefox\//i.test(ua)) browser = "Firefox";

    return { browser, os };
  }
}
