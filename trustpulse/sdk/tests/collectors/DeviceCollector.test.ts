import { describe, it, expect } from "vitest";
import { DeviceCollector } from "../../src/collectors/DeviceCollector";
import { PrivacyManager } from "../../src/privacy/PrivacyManager";

describe("DeviceCollector", () => {
  it("collects non-sensitive device and environment context", () => {
    const collector = new DeviceCollector(new PrivacyManager());
    const context = collector.getContext();

    expect(context).not.toBeNull();
    expect(context?.userAgentSummary.browser).toBeDefined();
    expect(context?.userAgentSummary.os).toBeDefined();
    expect(context?.screen.width).toBeDefined();
    expect(context?.screen.height).toBeDefined();
    expect(context?.screen.pixelRatio).toBeDefined();
    expect(context?.environment.language).toBeDefined();
    expect(context?.environment.timezoneOffset).toBeDefined();
  });

  it("returns null if device collection is disabled in privacy manager", () => {
    const pm = new PrivacyManager("standard", [], {
      collectTyping: true,
      collectMouse: true,
      collectClick: true,
      collectScroll: true,
      collectTouch: true,
      collectDevice: false,
    });
    const collector = new DeviceCollector(pm);
    const context = collector.getContext();
    expect(context).toBeNull();
  });
});
