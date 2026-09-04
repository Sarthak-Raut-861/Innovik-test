/**
 * @trustpulse/sdk - Structured Diagnostic Logger
 *
 * Emits diagnostic logs when debug mode is enabled.
 * Strictly guarantees that sensitive session tokens, passwords, raw keystrokes,
 * and payloads are never printed to the browser console.
 */
export class Logger {
    enabled;
    prefix = "[TrustPulse]";
    constructor(enabled = false) {
        this.enabled = enabled;
    }
    setEnabled(enabled) {
        this.enabled = enabled;
    }
    debug(message, ...args) {
        if (this.enabled) {
            // eslint-disable-next-line no-console
            console.debug(`${this.prefix} [DEBUG] ${message}`, ...this.sanitizeArgs(args));
        }
    }
    info(message, ...args) {
        if (this.enabled) {
            // eslint-disable-next-line no-console
            console.info(`${this.prefix} [INFO] ${message}`, ...this.sanitizeArgs(args));
        }
    }
    warn(message, ...args) {
        // Warnings are printed even when debug is off if critical, or conditionally
        if (this.enabled) {
            // eslint-disable-next-line no-console
            console.warn(`${this.prefix} [WARN] ${message}`, ...this.sanitizeArgs(args));
        }
    }
    error(message, ...args) {
        // Errors are always logged to facilitate integration troubleshooting
        // eslint-disable-next-line no-console
        console.error(`${this.prefix} [ERROR] ${message}`, ...this.sanitizeArgs(args));
    }
    /**
     * Defensive scrub of any objects passed to logging to prevent leaking potential secrets.
     */
    sanitizeArgs(args) {
        return args.map((arg) => {
            if (arg && typeof arg === "object") {
                try {
                    const sanitized = { ...arg };
                    const forbidden = ["password", "token", "secret", "authorization", "rawKey", "key", "otp", "code"];
                    for (const key of Object.keys(sanitized)) {
                        if (forbidden.some((f) => key.toLowerCase().includes(f))) {
                            sanitized[key] = "[REDACTED]";
                        }
                    }
                    return sanitized;
                }
                catch {
                    return "[Object]";
                }
            }
            return arg;
        });
    }
}
//# sourceMappingURL=Logger.js.map