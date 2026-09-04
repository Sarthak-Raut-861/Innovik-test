import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { TrustPulse } from "../../src/TrustPulse";
import { SDKInitializationError } from "../../src/errors/SDKError";

describe("TrustPulse SDK Full Lifecycle Integration", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ status: "accepted" }),
      })
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("progresses through complete state lifecycle correctly", async () => {
    const trustpulse = new TrustPulse({
      apiUrl: "https://api.trustpulse.security",
      publicKey: "pk_live_integration",
      sessionId: "session-init-123",
      debug: false,
    });

    expect(trustpulse.getStatus()).toBe("ready");
    expect(trustpulse.getSessionId()).toBe("session-init-123");
    expect(trustpulse.getSdkInstanceId()).toBeDefined();

    // Start
    trustpulse.start();
    expect(trustpulse.getStatus()).toBe("running");

    // Pause
    trustpulse.pause();
    expect(trustpulse.getStatus()).toBe("paused");

    // Resume
    trustpulse.resume();
    expect(trustpulse.getStatus()).toBe("running");

    // Flush
    await trustpulse.flush();
    expect(trustpulse.getStatus()).toBe("running");

    // Session update
    trustpulse.updateSession("session-rotated-456");
    expect(trustpulse.getSessionId()).toBe("session-rotated-456");

    // Stop
    trustpulse.stop();
    expect(trustpulse.getStatus()).toBe("stopped");

    // Destroy
    trustpulse.destroy();
    expect(trustpulse.getStatus()).toBe("destroyed");

    // Cannot start destroyed instance
    expect(() => trustpulse.start()).toThrow(SDKInitializationError);
  });
});
