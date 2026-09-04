import { describe, it, expect } from "vitest";
import { PrivacyManager } from "../../src/privacy/PrivacyManager";

describe("Privacy Manager", () => {
  it("identifies standard password input as sensitive", () => {
    const pm = new PrivacyManager();
    const input = document.createElement("input");
    input.type = "password";

    expect(pm.isElementSensitive(input)).toBe(true);
  });

  it("identifies autocomplete=current-password and new-password as sensitive", () => {
    const pm = new PrivacyManager();
    const inputCurrent = document.createElement("input");
    inputCurrent.autocomplete = "current-password";
    expect(pm.isElementSensitive(inputCurrent)).toBe(true);

    const inputNew = document.createElement("input");
    inputNew.autocomplete = "new-password";
    expect(pm.isElementSensitive(inputNew)).toBe(true);
  });

  it("identifies autocomplete=one-time-code (OTP) as sensitive", () => {
    const pm = new PrivacyManager();
    const otpInput = document.createElement("input");
    otpInput.autocomplete = "one-time-code";
    expect(pm.isElementSensitive(otpInput)).toBe(true);
  });

  it("identifies elements with data-trustpulse-ignore as sensitive", () => {
    const pm = new PrivacyManager();
    const input = document.createElement("input");
    input.setAttribute("data-trustpulse-ignore", "");
    expect(pm.isElementSensitive(input)).toBe(true);
  });

  it("identifies child elements inside data-trustpulse-ignore container as sensitive", () => {
    const pm = new PrivacyManager();
    const container = document.createElement("div");
    container.setAttribute("data-trustpulse-ignore", "true");

    const innerInput = document.createElement("input");
    container.appendChild(innerInput);
    document.body.appendChild(container);

    expect(pm.isElementSensitive(innerInput)).toBe(true);
    document.body.removeChild(container);
  });

  it("identifies sensitive names, ids, and credit card autocompletes", () => {
    const pm = new PrivacyManager();

    const cvvInput = document.createElement("input");
    cvvInput.name = "cvv";
    expect(pm.isElementSensitive(cvvInput)).toBe(true);

    const pinInput = document.createElement("input");
    pinInput.id = "user_pin";
    expect(pm.isElementSensitive(pinInput)).toBe(true);

    const ccInput = document.createElement("input");
    ccInput.autocomplete = "cc-number";
    expect(pm.isElementSensitive(ccInput)).toBe(true);
  });

  it("allows non-sensitive inputs like search or ordinary text fields", () => {
    const pm = new PrivacyManager();
    const searchInput = document.createElement("input");
    searchInput.type = "text";
    searchInput.name = "searchQuery";
    expect(pm.isElementSensitive(searchInput)).toBe(false);
  });

  it("produces sanitized non-content element descriptors without leaking text or values", () => {
    const pm = new PrivacyManager("standard");
    const button = document.createElement("button");
    button.textContent = "Transfer $50,000 to Account #987654";
    button.setAttribute("role", "button");

    const descriptor = pm.getSafeElementDescriptor(button);
    expect(descriptor).toBe("button[role=button]");
    expect(descriptor).not.toContain("Transfer");
    expect(descriptor).not.toContain("50,000");
    expect(descriptor).not.toContain("987654");
  });

  it("strict privacy mode returns generic tag name only", () => {
    const pm = new PrivacyManager("strict");
    const button = document.createElement("button");
    button.setAttribute("role", "submit-action");
    expect(pm.getSafeElementDescriptor(button)).toBe("button");
  });
});
