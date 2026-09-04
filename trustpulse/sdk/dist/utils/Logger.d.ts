/**
 * @trustpulse/sdk - Structured Diagnostic Logger
 *
 * Emits diagnostic logs when debug mode is enabled.
 * Strictly guarantees that sensitive session tokens, passwords, raw keystrokes,
 * and payloads are never printed to the browser console.
 */
export declare class Logger {
    private enabled;
    private readonly prefix;
    constructor(enabled?: boolean);
    setEnabled(enabled: boolean): void;
    debug(message: string, ...args: unknown[]): void;
    info(message: string, ...args: unknown[]): void;
    warn(message: string, ...args: unknown[]): void;
    error(message: string, ...args: unknown[]): void;
    /**
     * Defensive scrub of any objects passed to logging to prevent leaking potential secrets.
     */
    private sanitizeArgs;
}
//# sourceMappingURL=Logger.d.ts.map