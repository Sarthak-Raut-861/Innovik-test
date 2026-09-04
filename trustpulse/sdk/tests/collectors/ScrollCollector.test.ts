import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ScrollCollector } from "../../src/collectors/ScrollCollector";
import { PrivacyManager } from "../../src/privacy/PrivacyManager";

describe("ScrollCollector", () => {
  let collector: ScrollCollector;

  beforeEach(() => {
    collector = new ScrollCollector(new PrivacyManager());
    collector.start();
  });

  afterEach(() => {
    collector.stop();
  });

  it("handles scroll events and extracts relative delta", () => {
    window.scrollY = 250;
    window.dispatchEvent(new Event("scroll"));

    const samples = collector.getAndResetSamples();
    expect(samples.length).toBe(1);
    expect(samples[0]!.deltaY).toBe(250);
    expect(samples[0]!.timestamp).toBeGreaterThan(0);
  });

  it("handles empty scroll events cleanly", () => {
    expect(collector.getAndResetSamples()).toEqual([]);
  });
});
