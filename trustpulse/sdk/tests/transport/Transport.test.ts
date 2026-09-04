import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { TelemetryClient } from "../../src/transport/TelemetryClient";
import type { TelemetryBatch } from "../../src/telemetry/TelemetryTypes";

describe("TelemetryClient & RetryManager", () => {
  const mockBatch: TelemetryBatch = {
    batchId: "batch-1",
    sentAt: Date.now(),
    packets: [
      {
        sessionId: "sess-abc",
        sdkInstanceId: "inst-1",
        eventId: "evt-1",
        sequenceNumber: 1,
        timestamp: Date.now(),
        schemaVersion: "1.0.0",
        sdkVersion: "1.0.0",
        eventType: "behavioral_batch",
        features: { feature_schema_version: "1.0.0" },
      },
    ],
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sends batch successfully with correct security headers", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ status: "accepted" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const client = new TelemetryClient(
      "https://api.trustpulse.security",
      "pk_test_123",
      "sess-abc",
      2
    );

    const result = await client.sendBatch(mockBatch);
    expect(result.success).toBe(true);
    expect(result.status).toBe(200);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const callArgs = fetchMock.mock.calls[0]!;
    expect(callArgs[0]).toBe("https://api.trustpulse.security/v1/telemetry");
    const headers = callArgs[1].headers;
    expect(headers["X-TrustPulse-Public-Key"]).toBe("pk_test_123");
    expect(headers["X-TrustPulse-Session-Id"]).toBe("sess-abc");
    expect(headers["X-TrustPulse-SDK-Version"]).toBe("1.0.0");
  });

  it("retries on HTTP 500 error up to maxRetries", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
    });
    vi.stubGlobal("fetch", fetchMock);

    const client = new TelemetryClient(
      "https://api.trustpulse.security",
      "pk_test_123",
      "sess-abc",
      2 // max 2 retries = 3 attempts
    );

    const result = await client.sendBatch(mockBatch);
    expect(result.success).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("does not retry on non-retryable 401 client errors", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
    });
    vi.stubGlobal("fetch", fetchMock);

    const client = new TelemetryClient(
      "https://api.trustpulse.security",
      "pk_test_123",
      "sess-abc",
      3
    );

    const result = await client.sendBatch(mockBatch);
    expect(result.success).toBe(false);
    expect(result.status).toBe(401);
    // Should stop on first attempt
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("handles network failure without throwing uncaught exceptions", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("Failed to fetch"));
    vi.stubGlobal("fetch", fetchMock);

    const client = new TelemetryClient(
      "https://api.trustpulse.security",
      "pk_test_123",
      "sess-abc",
      1
    );

    const result = await client.sendBatch(mockBatch);
    expect(result.success).toBe(false);
    expect(result.status).toBe(0);
  });
});
