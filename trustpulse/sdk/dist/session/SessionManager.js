/**
 * @trustpulse/sdk - Session Manager
 *
 * Binds the SDK to the host application's authenticated session.
 * Manages SDK instance identification, session nonce, and lifecycle states.
 */
import { EventIdGenerator } from "../security/EventId";
import { NonceManager } from "../security/NonceManager";
import { TimeUtils } from "../utils/Time";
import { SessionBindingError } from "../errors/SDKError";
export class SessionManager {
    sessionId;
    sdkInstanceId;
    startTime;
    nonceManager;
    sessionNonce;
    state = "stopped";
    constructor(sessionId) {
        if (!sessionId || typeof sessionId !== "string" || sessionId.trim() === "") {
            throw new SessionBindingError("Invalid session ID provided during session binding.");
        }
        this.sessionId = sessionId.trim();
        this.sdkInstanceId = EventIdGenerator.generate();
        this.startTime = TimeUtils.epoch();
        this.nonceManager = new NonceManager();
        this.sessionNonce = this.nonceManager.generateNonce();
    }
    getSessionId() {
        return this.sessionId;
    }
    updateSessionId(newSessionId) {
        if (!newSessionId || typeof newSessionId !== "string" || newSessionId.trim() === "") {
            throw new SessionBindingError("Invalid new session ID provided for session update.");
        }
        this.sessionId = newSessionId.trim();
        this.nonceManager.reset();
    }
    getSdkInstanceId() {
        return this.sdkInstanceId;
    }
    getSessionContext() {
        return {
            sessionId: this.sessionId,
            sdkInstanceId: this.sdkInstanceId,
            startTime: this.startTime,
            sessionNonce: this.sessionNonce,
        };
    }
    nextSequence() {
        return this.nonceManager.nextSequence();
    }
    getSequence() {
        return this.nonceManager.getSequence();
    }
    getState() {
        return this.state;
    }
    start() {
        this.state = "active";
    }
    pause() {
        this.state = "paused";
    }
    resume() {
        this.state = "active";
    }
    stop() {
        this.state = "stopped";
    }
}
//# sourceMappingURL=SessionManager.js.map