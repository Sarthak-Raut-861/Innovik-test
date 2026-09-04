import { describe, it, expect } from "vitest";
import { SessionManager } from "../../src/session/SessionManager";
import { SessionBindingError } from "../../src/errors/SDKError";

describe("Session Manager", () => {
  it("initializes with valid session ID and generates unique instance ID", () => {
    const sessionManager = new SessionManager("session-12345");
    expect(sessionManager.getSessionId()).toBe("session-12345");

    const instanceId = sessionManager.getSdkInstanceId();
    expect(instanceId).toBeDefined();
    expect(typeof instanceId).toBe("string");
    expect(instanceId.length).toBeGreaterThan(10);

    const context = sessionManager.getSessionContext();
    expect(context.sessionId).toBe("session-12345");
    expect(context.sdkInstanceId).toBe(instanceId);
    expect(context.startTime).toBeGreaterThan(0);
    expect(context.sessionNonce).toBeDefined();
  });

  it("rejects empty or whitespace-only session IDs", () => {
    expect(() => new SessionManager("")).toThrow(SessionBindingError);
    expect(() => new SessionManager("   ")).toThrow(SessionBindingError);
  });

  it("generates monotonically increasing sequence numbers", () => {
    const sessionManager = new SessionManager("session-monotonic");
    expect(sessionManager.getSequence()).toBe(0);

    const s1 = sessionManager.nextSequence();
    const s2 = sessionManager.nextSequence();
    const s3 = sessionManager.nextSequence();

    expect(s1).toBe(1);
    expect(s2).toBe(2);
    expect(s3).toBe(3);
    expect(sessionManager.getSequence()).toBe(3);
  });

  it("updates session ID and resets sequence counter on session rotation", () => {
    const sessionManager = new SessionManager("initial-sess");
    sessionManager.nextSequence();
    sessionManager.nextSequence();
    expect(sessionManager.getSequence()).toBe(2);

    sessionManager.updateSessionId("rotated-sess");
    expect(sessionManager.getSessionId()).toBe("rotated-sess");
    expect(sessionManager.getSequence()).toBe(0);
  });

  it("manages session lifecycle states", () => {
    const sessionManager = new SessionManager("sess-lifecycle");
    expect(sessionManager.getState()).toBe("stopped");

    sessionManager.start();
    expect(sessionManager.getState()).toBe("active");

    sessionManager.pause();
    expect(sessionManager.getState()).toBe("paused");

    sessionManager.resume();
    expect(sessionManager.getState()).toBe("active");

    sessionManager.stop();
    expect(sessionManager.getState()).toBe("stopped");
  });
});
