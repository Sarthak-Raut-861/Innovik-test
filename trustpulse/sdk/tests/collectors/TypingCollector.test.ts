import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { TypingCollector } from "../../src/collectors/TypingCollector";
import { PrivacyManager } from "../../src/privacy/PrivacyManager";

describe("TypingCollector", () => {
  let privacyManager: PrivacyManager;
  let collector: TypingCollector;

  beforeEach(() => {
    privacyManager = new PrivacyManager();
    collector = new TypingCollector(privacyManager);
    collector.start();
  });

  afterEach(() => {
    collector.stop();
  });

  it("collects timing dynamics without capturing key characters or codes", () => {
    const input = document.createElement("input");
    input.type = "text";
    document.body.appendChild(input);

    const downEvent = new KeyboardEvent("keydown", { bubbles: true, cancelable: true });
    input.dispatchEvent(downEvent);

    const upEvent = new KeyboardEvent("keyup", { bubbles: true, cancelable: true });
    input.dispatchEvent(upEvent);

    const samples = collector.getAndResetSamples();
    expect(samples.length).toBe(1);
    expect(samples[0]!.dwellTime).toBeGreaterThanOrEqual(0);
    expect(samples[0]!.flightTime).toBe(0);

    // Verify ZERO raw character properties exist on samples
    expect((samples[0] as Record<string, unknown>)["key"]).toBeUndefined();
    expect((samples[0] as Record<string, unknown>)["code"]).toBeUndefined();
    expect((samples[0] as Record<string, unknown>)["char"]).toBeUndefined();
    expect((samples[0] as Record<string, unknown>)["text"]).toBeUndefined();

    document.body.removeChild(input);
  });

  it("strictly ignores keystrokes typed into password fields", () => {
    const passwordInput = document.createElement("input");
    passwordInput.type = "password";
    document.body.appendChild(passwordInput);

    passwordInput.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true }));
    passwordInput.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));

    const samples = collector.getAndResetSamples();
    expect(samples.length).toBe(0);

    document.body.removeChild(passwordInput);
  });

  it("strictly ignores keystrokes on elements with data-trustpulse-ignore", () => {
    const ignoredInput = document.createElement("input");
    ignoredInput.setAttribute("data-trustpulse-ignore", "true");
    document.body.appendChild(ignoredInput);

    ignoredInput.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true }));
    ignoredInput.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));

    const samples = collector.getAndResetSamples();
    expect(samples.length).toBe(0);

    document.body.removeChild(ignoredInput);
  });

  it("returns empty array and resets samples cleanly", () => {
    const initialSamples = collector.getAndResetSamples();
    expect(initialSamples).toEqual([]);

    collector.clear();
    expect(collector.getAndResetSamples()).toEqual([]);
  });
});
