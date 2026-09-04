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
import type { SessionContext, SessionLifecycleState } from "./SessionTypes";

export class SessionManager {
  private sessionId: string;
  private readonly sdkInstanceId: string;
  private readonly startTime: number;
  private readonly nonceManager: NonceManager;
  private readonly sessionNonce: string;
  private state: SessionLifecycleState = "stopped";

  constructor(sessionId: string) {
    if (!sessionId || typeof sessionId !== "string" || sessionId.trim() === "") {
      throw new SessionBindingError("Invalid session ID provided during session binding.");
    }
    this.sessionId = sessionId.trim();
    this.sdkInstanceId = EventIdGenerator.generate();
    this.startTime = TimeUtils.epoch();
    this.nonceManager = new NonceManager();
    this.sessionNonce = this.nonceManager.generateNonce();
  }

  public getSessionId(): string {
    return this.sessionId;
  }

  public updateSessionId(newSessionId: string): void {
    if (!newSessionId || typeof newSessionId !== "string" || newSessionId.trim() === "") {
      throw new SessionBindingError("Invalid new session ID provided for session update.");
    }
    this.sessionId = newSessionId.trim();
    this.nonceManager.reset();
  }

  public getSdkInstanceId(): string {
    return this.sdkInstanceId;
  }

  public getSessionContext(): SessionContext {
    return {
      sessionId: this.sessionId,
      sdkInstanceId: this.sdkInstanceId,
      startTime: this.startTime,
      sessionNonce: this.sessionNonce,
    };
  }

  public nextSequence(): number {
    return this.nonceManager.nextSequence();
  }

  public getSequence(): number {
    return this.nonceManager.getSequence();
  }

  public getState(): SessionLifecycleState {
    return this.state;
  }

  public start(): void {
    this.state = "active";
  }

  public pause(): void {
    this.state = "paused";
  }

  public resume(): void {
    this.state = "active";
  }

  public stop(): void {
    this.state = "stopped";
  }
}
