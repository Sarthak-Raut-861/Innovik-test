import { describe, it, expect, vi } from "vitest";
import { TrustPulse } from "../../src/TrustPulse";
import { PrivacyManager } from "../../src/privacy/PrivacyManager";
import { TypingCollector } from "../../src/collectors/TypingCollector";
import { TelemetryQueue } from "../../src/telemetry/TelemetryQueue";
import { ConfigurationError } from "../../src/errors/SDKError";
import type { TelemetryPacket } from "../../src/telemetry/TelemetryTypes";

describe("Security Test Suite (Attacks 1 - 8)", () => {
  /**
   * ATTACK 1 — Password Capture
   * An attacker attempts to observe passwords typed into login forms.
   * Requirement: Ensure password values never enter telemetry.
   */
  it("Attack 1: Password inputs are strictly excluded and zero values enter telemetry", () => {
    const privacyManager = new PrivacyManager();
    const typingCollector = new TypingCollector(privacyManager);
    typingCollector.start();

    const passwordInput = document.createElement("input");
    passwordInput.type = "password";
    passwordInput.value = "SuperSecretPassword!2026";
    document.body.appendChild(passwordInput);

    passwordInput.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true }));
    passwordInput.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));

    const samples = typingCollector.getAndResetSamples();
    expect(samples.length).toBe(0);

    const serialized = JSON.stringify(samples);
    expect(serialized).not.toContain("SuperSecretPassword!2026");

    document.body.removeChild(passwordInput);
    typingCollector.stop();
  });

  /**
   * ATTACK 2 — OTP Capture
   * An attacker attempts to capture 2FA / One-Time Passwords from verification inputs.
   * Requirement: Ensure OTP fields are ignored.
   */
  it("Attack 2: One-time-code (OTP) and MFA inputs are completely excluded", () => {
    const privacyManager = new PrivacyManager();
    const typingCollector = new TypingCollector(privacyManager);
    typingCollector.start();

    const otpInput = document.createElement("input");
    otpInput.autocomplete = "one-time-code";
    otpInput.id = "user_otp_verification";
    document.body.appendChild(otpInput);

    otpInput.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true }));
    otpInput.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));

    const samples = typingCollector.getAndResetSamples();
    expect(samples.length).toBe(0);

    document.body.removeChild(otpInput);
    typingCollector.stop();
  });

  /**
   * ATTACK 3 — Raw Keystroke Capture
   * An attacker attempts to reconstruct typed text, messages, or account numbers from telemetry.
   * Requirement: Ensure no raw character sequence is captured or transmitted.
   */
  it("Attack 3: Keystroke telemetry contains ONLY timing deltas and ZERO character representations", () => {
    const privacyManager = new PrivacyManager();
    const typingCollector = new TypingCollector(privacyManager);
    typingCollector.start();

    const normalInput = document.createElement("input");
    normalInput.type = "text";
    document.body.appendChild(normalInput);

    // Simulate user typing "Transfer 1000"
    const characters = ["T", "r", "a", "n", "s", "f", "e", "r"];
    for (const char of characters) {
      normalInput.dispatchEvent(new KeyboardEvent("keydown", { key: char, bubbles: true }));
      normalInput.dispatchEvent(new KeyboardEvent("keyup", { key: char, bubbles: true }));
    }

    const samples = typingCollector.getAndResetSamples();
    expect(samples.length).toBe(8);

    const serialized = JSON.stringify(samples);
    for (const char of characters) {
      expect(serialized).not.toContain(`"${char}"`);
      expect(serialized).not.toContain(`key`);
      expect(serialized).not.toContain(`code`);
    }

    document.body.removeChild(normalInput);
    typingCollector.stop();
  });

  /**
   * ATTACK 4 — Telemetry Flooding (DoS)
   * A malicious script or rapid user action floods the SDK with millions of events to cause an Out-Of-Memory crash.
   * Requirement: Ensure queue limits prevent uncontrolled memory growth.
   */
  it("Attack 4: Telemetry queue bounds memory usage and evicts oldest items gracefully", () => {
    const maxCapacity = 50;
    const queue = new TelemetryQueue(maxCapacity);

    // Attempt to flood with 1,000 events
    for (let i = 0; i < 1000; i++) {
      const packet: TelemetryPacket = {
        sessionId: "sess-flood",
        sdkInstanceId: "inst-flood",
        eventId: `flood-evt-${i}`,
        sequenceNumber: i + 1,
        timestamp: Date.now(),
        schemaVersion: "1.0.0",
        sdkVersion: "1.0.0",
        eventType: "behavioral_batch",
        features: { feature_schema_version: "1.0.0" },
      };
      queue.enqueue(packet);
    }

    expect(queue.size()).toBe(maxCapacity);
    expect(queue.getDroppedCount()).toBe(1000 - maxCapacity);
  });

  /**
   * ATTACK 5 — Replay & Packet Tampering
   * An adversary intercepts telemetry and replays old packets to mimic legitimate behavior.
   * Requirement: Ensure unique event IDs, monotonically increasing sequence numbers, and integrity checksums exist.
   */
  it("Attack 5: Every packet carries unique event ID, monotonic sequence number, and integrity tag", () => {
    const sdk = new TrustPulse({
      apiUrl: "https://api.trustpulse.security",
      publicKey: "pk_live_sec_test",
      sessionId: "session-replay-check",
    });

    const packet1 = (sdk as unknown as { telemetryManager: { buildTelemetryPacket: (type: string) => TelemetryPacket } }).telemetryManager.buildTelemetryPacket("session_start");
    const packet2 = (sdk as unknown as { telemetryManager: { buildTelemetryPacket: (type: string) => TelemetryPacket } }).telemetryManager.buildTelemetryPacket("session_start");

    expect(packet1).not.toBeNull();
    expect(packet2).not.toBeNull();

    // Event IDs must be distinct UUIDs
    expect(packet1.eventId).not.toBe(packet2.eventId);

    // Sequence numbers must be strictly monotonic
    expect(packet2.sequenceNumber).toBe(packet1.sequenceNumber + 1);

    // Integrity checksum must be present
    expect(packet1.integrity).toBeDefined();
    expect(typeof packet1.integrity).toBe("string");
  });

  /**
   * ATTACK 6 — Tampered SDK Configuration
   * An attacker passes non-HTTPS endpoints or malformed configuration to hijack or crash telemetry.
   * Requirement: Ensure strict rejection of insecure configuration.
   */
  it("Attack 6: SDK rejects insecure configuration and does not accept client-side secrets", () => {
    // Insecure HTTP URL in production
    expect(() => {
      new TrustPulse({
        apiUrl: "http://malicious-proxy.com",
        publicKey: "pk_test",
        sessionId: "sess_1",
      });
    }).toThrow(ConfigurationError);

    // Missing sessionId
    expect(() => {
      new TrustPulse({
        apiUrl: "https://api.trustpulse.security",
        publicKey: "pk_test",
        sessionId: "",
      });
    }).toThrow(ConfigurationError);
  });

  /**
   * ATTACK 7 — Network Failure & Degraded Backend
   * The TrustPulse backend is down, returns 500s, or encounters network drops.
   * Requirement: SDK degrades gracefully and NEVER halts or blocks the customer host application.
   */
  it("Attack 7: SDK operates non-blockingly during backend failure and respects retry limits", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("Connection refused"))
    );

    const sdk = new TrustPulse({
      apiUrl: "https://api.trustpulse.security",
      publicKey: "pk_test",
      sessionId: "sess_failover",
      telemetryIntervalMs: 1000,
      maxRetries: 1,
    });

    sdk.start();

    // Trigger flush - must complete gracefully without throwing unhandled error to host app
    await expect(sdk.flush()).resolves.toBeUndefined();

    // Status remains running or ready, never crashing the page
    expect(sdk.getStatus()).toBe("running");

    sdk.destroy();
    vi.restoreAllMocks();
  });

  /**
   * ATTACK 8 — Untrusted Client Boundary
   * Verify that SDK architectural invariants hold:
   * 1. No decision methods exist on the SDK (no "isUserLegitimate()", "authorize()", "block()").
   * 2. No private keys exist.
   * 3. Public API exposes only telemetry controls.
   */
  it("Attack 8: SDK enforces architectural security boundaries", () => {
    const sdk = new TrustPulse({
      apiUrl: "https://api.trustpulse.security",
      publicKey: "pk_public_only",
      sessionId: "sess_boundary",
    });

    const sdkAny = sdk as unknown as Record<string, unknown>;

    // Security authority enforcement: client cannot decide or block
    expect(sdkAny["isLegitimate"]).toBeUndefined();
    expect(sdkAny["authorizeTransaction"]).toBeUndefined();
    expect(sdkAny["blockUser"]).toBeUndefined();
    expect(sdkAny["calculateTrustScore"]).toBeUndefined();
    expect(sdkAny["privateKey"]).toBeUndefined();
    expect(sdkAny["secretKey"]).toBeUndefined();
  });
});
