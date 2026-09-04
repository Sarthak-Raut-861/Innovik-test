/**
 * @trustpulse/sdk - Retry Policy Manager
 *
 * Implements bounded exponential backoff with decorrelated full jitter
 * to prevent thundering herd problems during backend degradation.
 */
export declare class RetryManager {
    private readonly baseDelayMs;
    private readonly maxDelayMs;
    private readonly backoffFactor;
    constructor(baseDelayMs?: number, maxDelayMs?: number, backoffFactor?: number);
    /**
     * Calculates backoff duration with randomized jitter.
     */
    calculateDelay(attempt: number): number;
    /**
     * Safe asynchronous delay.
     */
    delay(attempt: number): Promise<void>;
}
//# sourceMappingURL=RetryManager.d.ts.map