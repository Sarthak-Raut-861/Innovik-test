/**
 * @trustpulse/sdk - Mouse Kinematics Collector
 *
 * Collects relative movement dynamics (distances, velocities, angular changes).
 * Raw coordinate streams are NEVER transmitted to the server; they are buffered
 * locally only long enough to extract aggregate statistical features.
 */
import { BaseCollector } from "./BaseCollector";
import { TimeUtils } from "../utils/Time";
import { BrowserUtils } from "../utils/Browser";
export class MouseCollector extends BaseCollector {
    privacyManager;
    samples = [];
    lastSampleTime = 0;
    sampleThrottleMs = 16; // ~60 Hz sampling cap
    maxSamples;
    boundMouseMove;
    constructor(privacyManager, maxSamples = 200) {
        super();
        this.privacyManager = privacyManager;
        this.maxSamples = maxSamples;
        this.boundMouseMove = this.handleMouseMove.bind(this);
    }
    start() {
        if (this.active || !BrowserUtils.isBrowser())
            return;
        this.active = true;
        this.paused = false;
        window.addEventListener("mousemove", this.boundMouseMove, { capture: true, passive: true });
    }
    stop() {
        if (!this.active || !BrowserUtils.isBrowser())
            return;
        this.active = false;
        this.paused = false;
        window.removeEventListener("mousemove", this.boundMouseMove, { capture: true });
        this.clear();
    }
    clear() {
        this.samples = [];
        this.lastSampleTime = 0;
    }
    getAndResetSamples() {
        const extracted = this.samples;
        this.samples = [];
        return extracted;
    }
    handleMouseMove(event) {
        if (!this.isActive() || !this.privacyManager.isMouseEnabled())
            return;
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
//# sourceMappingURL=MouseCollector.js.map