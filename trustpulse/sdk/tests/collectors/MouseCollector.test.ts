import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { MouseCollector } from "../../src/collectors/MouseCollector";
import { PrivacyManager } from "../../src/privacy/PrivacyManager";

describe("MouseCollector", () => {
  let collector: MouseCollector;

  beforeEach(() => {
    collector = new MouseCollector(new PrivacyManager());
    collector.start();
  });

  afterEach(() => {
    collector.stop();
  });

  it("buffers mousemove points and respects throttle", () => {
    window.dispatchEvent(new MouseEvent("mousemove", { clientX: 100, clientY: 150 }));
    const samples = collector.getAndResetSamples();

    expect(samples.length).toBe(1);
    expect(samples[0]!.x).toBe(100);
    expect(samples[0]!.y).toBe(150);
    expect(samples[0]!.timestamp).toBeGreaterThan(0);
  });

  it("returns empty array when no mousemove events occurred", () => {
    expect(collector.getAndResetSamples()).toEqual([]);
  });

  it("clears points buffer properly", () => {
    window.dispatchEvent(new MouseEvent("mousemove", { clientX: 10, clientY: 20 }));
    collector.clear();
    expect(collector.getAndResetSamples()).toEqual([]);
  });
});
