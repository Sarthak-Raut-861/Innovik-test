/**
 * @trustpulse/sdk - Scroll Dynamics Collector
 *
 * Collects relative scroll movement dynamics (velocities, frequencies, pause durations).
 * Avoids recording exact page positions or content identifiers.
 */
import { BaseCollector } from "./BaseCollector";
import { TimeUtils } from "../utils/Time";
import { BrowserUtils } from "../utils/Browser";
export class ScrollCollector extends BaseCollector {
    privacyManager;
    samples = [];
    lastScrollTime = 0;
    lastScrollY = 0;
    sampleThrottleMs = 30;
    maxSamples;
    boundScrollHandler;
    constructor(privacyManager, maxSamples = 100) {
        super();
        this.privacyManager = privacyManager;
        this.maxSamples = maxSamples;
        this.boundScrollHandler = this.handleScroll.bind(this);
    }
    start() {
        if (this.active || !BrowserUtils.isBrowser())
            return;
        this.active = true;
        this.paused = false;
        this.lastScrollY = window.scrollY || window.pageYOffset || 0;
        window.addEventListener("scroll", this.boundScrollHandler, { capture: true, passive: true });
    }
    stop() {
        if (!this.active || !BrowserUtils.isBrowser())
            return;
        this.active = false;
        this.paused = false;
        window.removeEventListener("scroll", this.boundScrollHandler, { capture: true });
        this.clear();
    }
    clear() {
        this.samples = [];
        this.lastScrollTime = 0;
        this.lastScrollY = 0;
    }
    getAndResetSamples() {
        const extracted = this.samples;
        this.samples = [];
        return extracted;
    }
    handleScroll() {
        if (!this.isActive() || !this.privacyManager.isScrollEnabled())
            return;
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
//# sourceMappingURL=ScrollCollector.js.map