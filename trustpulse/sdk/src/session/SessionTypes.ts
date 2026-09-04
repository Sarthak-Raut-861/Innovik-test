/**
 * @trustpulse/sdk - Session Types
 */

export interface SessionContext {
  sessionId: string;
  sdkInstanceId: string;
  startTime: number;
  sessionNonce: string;
}

export type SessionLifecycleState = "active" | "paused" | "stopped";
