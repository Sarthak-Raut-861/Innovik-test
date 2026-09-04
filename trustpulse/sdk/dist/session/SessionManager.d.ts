/**
 * @trustpulse/sdk - Session Manager
 *
 * Binds the SDK to the host application's authenticated session.
 * Manages SDK instance identification, session nonce, and lifecycle states.
 */
import type { SessionContext, SessionLifecycleState } from "./SessionTypes";
export declare class SessionManager {
    private sessionId;
    private readonly sdkInstanceId;
    private readonly startTime;
    private readonly nonceManager;
    private readonly sessionNonce;
    private state;
    constructor(sessionId: string);
    getSessionId(): string;
    updateSessionId(newSessionId: string): void;
    getSdkInstanceId(): string;
    getSessionContext(): SessionContext;
    nextSequence(): number;
    getSequence(): number;
    getState(): SessionLifecycleState;
    start(): void;
    pause(): void;
    resume(): void;
    stop(): void;
}
//# sourceMappingURL=SessionManager.d.ts.map