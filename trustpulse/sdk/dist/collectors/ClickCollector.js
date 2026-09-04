/**
 * @trustpulse/sdk - Click Dynamics Collector
 *
 * Collects click timing intervals, double-click cadences, and aggregate frequency.
 * Strictly guarantees that button labels, input contents, account numbers, or
 * transaction amounts are NEVER inspected or captured.
 */
import { BaseCollector } from "./BaseCollector";
import { TimeUtils } from "../utils/Time";
import { BrowserUtils } from "../utils/Browser";
export class ClickCollector extends BaseCollector {
    privacyManager;
    samples = [];
    lastClickTime = null;
    maxSamples;
    doubleClickThresholdMs = 350;
    boundClickHandler;
    constructor(privacyManager, maxSamples = 100) {
        super();
        this.privacyManager = privacyManager;
        this.maxSamples = maxSamples;
        this.boundClickHandler = this.handleClick.bind(this);
    }
    start() {
        if (this.active || !BrowserUtils.isBrowser())
            return;
        this.active = true;
        this.paused = false;
        window.addEventListener("click", this.boundClickHandler, { capture: true, passive: true });
    }
    stop() {
        if (!this.active || !BrowserUtils.isBrowser())
            return;
        this.active = false;
        this.paused = false;
        window.removeEventListener("click", this.boundClickHandler, { capture: true });
        this.clear();
    }
    clear() {
        this.samples = [];
        this.lastClickTime = null;
    }
    getAndResetSamples() {
        const extracted = this.samples;
        this.samples = [];
        return extracted;
    }
    handleClick(event) {
        if (!this.isActive() || !this.privacyManager.isClickEnabled())
            return;
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
//# sourceMappingURL=ClickCollector.js.map