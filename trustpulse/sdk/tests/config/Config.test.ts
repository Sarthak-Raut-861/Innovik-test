import { describe, it, expect } from "vitest";
import { validateConfig } from "../../src/config/validator";
import { ConfigurationError } from "../../src/errors/SDKError";

describe("Configuration Validation", () => {
  const validConfig = {
    apiUrl: "https://api.trustpulse.security",
    publicKey: "pk_live_customer123",
    sessionId: "sess_user_abc456",
  };

  it("accepts valid HTTPS configuration with defaults", () => {
    const validated = validateConfig(validConfig);
    expect(validated.apiUrl).toBe("https://api.trustpulse.security");
    expect(validated.publicKey).toBe("pk_live_customer123");
    expect(validated.sessionId).toBe("sess_user_abc456");
    expect(validated.telemetryIntervalMs).toBe(3000);
    expect(validated.maxQueueSize).toBe(500);
    expect(validated.batchSize).toBe(10);
    expect(validated.maxRetries).toBe(3);
    expect(validated.privacyMode).toBe("standard");
    expect(validated.debug).toBe(false);
  });

  it("allows localhost HTTP in development", () => {
    const localhostConfig = {
      ...validConfig,
      apiUrl: "http://localhost:8000",
    };
    const validated = validateConfig(localhostConfig);
    expect(validated.apiUrl).toBe("http://localhost:8000");
  });

  it("rejects non-HTTPS apiUrl in production", () => {
    expect(() => {
      validateConfig({
        ...validConfig,
        apiUrl: "http://api.trustpulse.security",
      });
    }).toThrow(ConfigurationError);
  });

  it("rejects invalid URL formats", () => {
    expect(() => {
      validateConfig({
        ...validConfig,
        apiUrl: "not-a-url",
      });
    }).toThrow(ConfigurationError);
  });

  it("rejects missing or empty publicKey", () => {
    expect(() => {
      validateConfig({
        ...validConfig,
        publicKey: "",
      });
    }).toThrow(ConfigurationError);
  });

  it("rejects missing or empty sessionId", () => {
    expect(() => {
      validateConfig({
        ...validConfig,
        sessionId: "   ",
      });
    }).toThrow(ConfigurationError);
  });

  it("enforces telemetryIntervalMs bounds", () => {
    expect(() => {
      validateConfig({
        ...validConfig,
        telemetryIntervalMs: 500, // < 1000ms
      });
    }).toThrow(ConfigurationError);

    expect(() => {
      validateConfig({
        ...validConfig,
        telemetryIntervalMs: 120000, // > 60000ms
      });
    }).toThrow(ConfigurationError);
  });

  it("rejects invalid privacyMode", () => {
    expect(() => {
      validateConfig({
        ...validConfig,
        // @ts-expect-error test invalid mode
        privacyMode: "ultra-permissive",
      });
    }).toThrow(ConfigurationError);
  });
});
