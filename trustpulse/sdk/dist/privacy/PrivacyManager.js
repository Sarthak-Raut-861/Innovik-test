/**
 * @trustpulse/sdk - Privacy Manager
 *
 * Implements strict privacy boundaries, sensitive element exclusion,
 * and zero-content guarantees across all behavioral collectors.
 */
export class PrivacyManager {
    config;
    // Standard selectors that identify sensitive inputs
    static SENSITIVE_SELECTORS = [
        'input[type="password"]',
        'input[autocomplete*="password"]',
        'input[autocomplete="one-time-code"]',
        'input[autocomplete*="cc-"]',
        'input[name*="password" i]',
        'input[name*="otp" i]',
        'input[name*="cvv" i]',
        'input[name*="pin" i]',
        'input[name*="ssn" i]',
        '[data-trustpulse-ignore]',
        '[data-trustpulse-ignore] *',
    ];
    // Regex patterns to detect sensitive attributes in names or IDs
    static SENSITIVE_PATTERN = /(?:password|passwd|pwd|passcode|secret|otp|token|pin|ssn|cvv|cvc|cardnumber|creditcard|authcode)/i;
    constructor(privacyMode = "standard", ignoredSelectors = [], signalToggles = {
        collectTyping: true,
        collectMouse: true,
        collectClick: true,
        collectScroll: true,
        collectTouch: true,
        collectDevice: true,
    }) {
        this.config = {
            ...signalToggles,
            localFeatureExtraction: true,
            privacyMode,
            ignoredSelectors,
        };
    }
    getPrivacyMode() {
        return this.config.privacyMode;
    }
    setPrivacyMode(mode) {
        this.config.privacyMode = mode;
    }
    isTypingEnabled() {
        return this.config.collectTyping;
    }
    isMouseEnabled() {
        return this.config.collectMouse;
    }
    isClickEnabled() {
        return this.config.collectClick;
    }
    isScrollEnabled() {
        return this.config.collectScroll;
    }
    isTouchEnabled() {
        return this.config.collectTouch;
    }
    isDeviceEnabled() {
        return this.config.collectDevice;
    }
    /**
     * Evaluates whether an event target is an ignored or sensitive field.
     * If true, behavioral observers must completely skip processing the event.
     */
    isElementSensitive(target) {
        if (!target || typeof target.tagName === "undefined") {
            return false;
        }
        const el = target;
        // Check data-trustpulse-ignore directly or in ancestor tree
        if (typeof el.closest === "function" && el.closest("[data-trustpulse-ignore]")) {
            return true;
        }
        // Check custom ignored selectors
        for (const selector of this.config.ignoredSelectors) {
            try {
                if (typeof el.matches === "function" && el.matches(selector)) {
                    return true;
                }
                if (typeof el.closest === "function" && el.closest(selector)) {
                    return true;
                }
            }
            catch {
                // Invalid selector, skip
            }
        }
        // Check standard sensitive selectors
        for (const selector of PrivacyManager.SENSITIVE_SELECTORS) {
            try {
                if (typeof el.matches === "function" && el.matches(selector)) {
                    return true;
                }
            }
            catch {
                // Skip
            }
        }
        // Check element attributes for sensitive naming
        const inputEl = el;
        if (inputEl.type === "password") {
            return true;
        }
        const name = inputEl.name || "";
        const id = inputEl.id || "";
        const autocomplete = inputEl.autocomplete || "";
        const ariaLabel = inputEl.getAttribute("aria-label") || "";
        if (PrivacyManager.SENSITIVE_PATTERN.test(name) ||
            PrivacyManager.SENSITIVE_PATTERN.test(id) ||
            PrivacyManager.SENSITIVE_PATTERN.test(autocomplete) ||
            PrivacyManager.SENSITIVE_PATTERN.test(ariaLabel)) {
            return true;
        }
        return false;
    }
    /**
     * Produces a sanitized, non-content structural identifier for an element.
     * NEVER extracts innerText, textContent, or input values.
     */
    getSafeElementDescriptor(target) {
        if (!target || typeof target.tagName === "undefined") {
            return "unknown";
        }
        // In strict mode, only return the generic tag name
        if (this.config.privacyMode === "strict") {
            return target.tagName.toLowerCase();
        }
        const el = target;
        const tag = el.tagName.toLowerCase();
        // If sensitive, return generic tag
        if (this.isElementSensitive(el)) {
            return `${tag}[sensitive]`;
        }
        // Return safe sanitized identifier (tag only or generic role)
        const role = el.getAttribute("role");
        if (role && !PrivacyManager.SENSITIVE_PATTERN.test(role)) {
            return `${tag}[role=${role.slice(0, 20)}]`;
        }
        return tag;
    }
}
//# sourceMappingURL=PrivacyManager.js.map