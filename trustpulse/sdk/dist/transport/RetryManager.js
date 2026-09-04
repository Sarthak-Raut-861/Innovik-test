/**
 * @trustpulse/sdk - Retry Policy Manager
 *
 * Implements bounded exponential backoff with decorrelated full jitter
 * to prevent thundering herd problems during backend degradation.
 */
export class RetryManager {
    baseDelayMs;
    maxDelayMs;
    backoffFactor;
    constructor(baseDelayMs = 500, maxDelayMs = 10000, backoffFactor = 2) {
        this.baseDelayMs = baseDelayMs;
        this.maxDelayMs = maxDelayMs;
        this.backoffFactor = backoffFactor;
    }
    /**
     * Calculates backoff duration with randomized jitter.
     */
    calculateDelay(attempt) {
        const rawDelay = this.baseDelayMs * Math.pow(this.backoffFactor, attempt);
        const cappedDelay = Math.min(rawDelay, this.maxDelayMs);
        // Add jitter +/- 20%
        const jitter = 0.8 + Math.random() * 0.4;
        return Math.round(cappedDelay * jitter);
    }
    /**
     * Safe asynchronous delay.
     */
    async delay(attempt) {
        const ms = this.calculateDelay(attempt);
        return new Promise((resolve) => {
            setTimeout(resolve, ms);
        });
    }
}
//# sourceMappingURL=RetryManager.js.map