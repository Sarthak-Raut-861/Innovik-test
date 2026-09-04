/**
 * @trustpulse/sdk - Base Collector Abstraction
 *
 * Provides a standardized lifecycle and safe event listener management
 * across all behavioral collectors.
 */
export class BaseCollector {
    active = false;
    paused = false;
    pause() {
        this.paused = true;
    }
    resume() {
        this.paused = false;
    }
    isActive() {
        return this.active && !this.paused;
    }
}
//# sourceMappingURL=BaseCollector.js.map