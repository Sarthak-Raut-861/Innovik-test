import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ClickCollector } from "../../src/collectors/ClickCollector";
import { PrivacyManager } from "../../src/privacy/PrivacyManager";

describe("ClickCollector", () => {
  let collector: ClickCollector;

  beforeEach(() => {
    collector = new ClickCollector(new PrivacyManager());
    collector.start();
  });

  afterEach(() => {
    collector.stop();
  });

  it("records click interval and identifies double click", async () => {
    const btn = document.createElement("button");
    btn.textContent = "Submit Payment";
    document.body.appendChild(btn);

    btn.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    // Immediate second click (burst / double click)
    btn.dispatchEvent(new MouseEvent("click", { bubbles: true }));

    const samples = collector.getAndResetSamples();
    expect(samples.length).toBe(2);
    expect(samples[0]!.elementCategory).toBe("button");
    // Text "Submit Payment" must never be stored
    expect(JSON.stringify(samples[0])).not.toContain("Submit Payment");
    expect(samples[1]!.isDoubleClick).toBe(true);

    document.body.removeChild(btn);
  });

  it("handles empty stream", () => {
    expect(collector.getAndResetSamples()).toEqual([]);
  });
});
