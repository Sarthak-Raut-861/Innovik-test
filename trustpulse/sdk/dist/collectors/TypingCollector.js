/**
 * @trustpulse/sdk - Privacy-Preserving Typing Collector
 *
 * Collects keypress timing dynamics (dwell times and flight times) strictly.
 * ZERO character values, key codes, text strings, or form values are ever accessed.
 * Sensitive fields (passwords, OTPs, PINs, card numbers, ignored fields) are completely excluded.
 */
import { BaseCollector } from "./BaseCollector";
import { TimeUtils } from "../utils/Time";
import { BrowserUtils } from "../utils/Browser";
export class TypingCollector extends BaseCollector {
    privacyManager;
    keydownTime = null;
    lastKeyupTime = null;
    samples = [];
    maxSamples;
    // Bound event handlers for clean registration and deregistration
    boundKeyDown;
    boundKeyUp;
    constructor(privacyManager, maxSamples = 100) {
        super();
        this.privacyManager = privacyManager;
        this.maxSamples = maxSamples;
        this.boundKeyDown = this.handleKeyDown.bind(this);
        this.boundKeyUp = this.handleKeyUp.bind(this);
    }
    start() {
        if (this.active || !BrowserUtils.isBrowser())
            return;
        this.active = true;
        this.paused = false;
        window.addEventListener("keydown", this.boundKeyDown, { capture: true, passive: true });
        window.addEventListener("keyup", this.boundKeyUp, { capture: true, passive: true });
    }
    stop() {
        if (!this.active || !BrowserUtils.isBrowser())
            return;
        this.active = false;
        this.paused = false;
        window.removeEventListener("keydown", this.boundKeyDown, { capture: true });
        window.removeEventListener("keyup", this.boundKeyUp, { capture: true });
        this.clear();
    }
    clear() {
        this.samples = [];
        this.keydownTime = null;
        this.lastKeyupTime = null;
    }
    getAndResetSamples() {
        const extracted = this.samples;
        this.samples = [];
        return extracted;
    }
    handleKeyDown(event) {
        if (!this.isActive() || !this.privacyManager.isTypingEnabled())
            return;
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
    handleKeyUp(event) {
        if (!this.isActive() || !this.privacyManager.isTypingEnabled())
            return;
        // Strict Privacy Gate
        if (this.privacyManager.isElementSensitive(event.target)) {
            this.keydownTime = null;
            this.lastKeyupTime = null;
            return;
        }
        if (this.keydownTime === null)
            return;
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
//# sourceMappingURL=TypingCollector.js.map