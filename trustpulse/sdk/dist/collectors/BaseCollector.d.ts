/**
 * @trustpulse/sdk - Base Collector Abstraction
 *
 * Provides a standardized lifecycle and safe event listener management
 * across all behavioral collectors.
 */
export declare abstract class BaseCollector {
    protected active: boolean;
    protected paused: boolean;
    abstract start(): void;
    abstract stop(): void;
    abstract clear(): void;
    pause(): void;
    resume(): void;
    isActive(): boolean;
}
//# sourceMappingURL=BaseCollector.d.ts.map