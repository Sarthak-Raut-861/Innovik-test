/**
 * @trustpulse/sdk - Non-Sensitive Device Context Collector
 *
 * Collects technical context (platform, display properties, capability indicators).
 * In accordance with Core Rule 3 ("Behavior is evidence, not identity"), this does
 * NOT claim to create a unique identifier or deterministic device fingerprint.
 */
import { BaseCollector } from "./BaseCollector";
import { BrowserUtils } from "../utils/Browser";
export class DeviceCollector extends BaseCollector {
    privacyManager;
    cachedContext = null;
    constructor(privacyManager) {
        super();
        this.privacyManager = privacyManager;
    }
    start() {
        if (this.active)
            return;
        this.active = true;
        this.paused = false;
        this.refresh();
    }
    stop() {
        this.active = false;
        this.paused = false;
    }
    clear() {
        this.cachedContext = null;
    }
    refresh() {
        if (!BrowserUtils.isBrowser() || !this.privacyManager.isDeviceEnabled()) {
            return null;
        }
        const nav = navigator;
        const scr = window.screen;
        let tz;
        try {
            tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        }
        catch {
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
    getContext() {
        if (!this.cachedContext) {
            return this.refresh();
        }
        return this.cachedContext;
    }
    parseUserAgent(ua) {
        let browser = "Other";
        let os = "Other";
        if (/Windows/i.test(ua))
            os = "Windows";
        else if (/Macintosh|Mac OS/i.test(ua))
            os = "macOS";
        else if (/Android/i.test(ua))
            os = "Android";
        else if (/iPhone|iPad|iPod/i.test(ua))
            os = "iOS";
        else if (/Linux/i.test(ua))
            os = "Linux";
        if (/Edg\//i.test(ua))
            browser = "Edge";
        else if (/Chrome\//i.test(ua) && !/Chromium|Edg/i.test(ua))
            browser = "Chrome";
        else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua))
            browser = "Safari";
        else if (/Firefox\//i.test(ua))
            browser = "Firefox";
        return { browser, os };
    }
}
//# sourceMappingURL=DeviceCollector.js.map