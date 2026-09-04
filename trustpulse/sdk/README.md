# @trustpulse/sdk

> **Production-Grade Continuous Session Security Telemetry SDK for Modern Web Applications**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Vitest](https://img.shields.io/badge/Tests-Vitest%20Passed-brightgreen.svg)](https://vitest.dev/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)]()

---

> [!IMPORTANT]
> **Core Security Principle**: TrustPulse provides continuous security evidence. It does not establish absolute identity and does not replace authentication, authorization, endpoint security, or Multi-Factor Authentication (MFA).

---

## Table of Contents
1. [What is TrustPulse AI?](#what-is-trustpulse-ai)
2. [Why TrustPulse Exists](#why-trustpulse-exists)
3. [Architecture Overview](#architecture-overview)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [Configuration Reference](#configuration-reference)
7. [Privacy Architecture & Zero-Content Guarantee](#privacy-architecture--zero-content-guarantee)
8. [Security Model](#security-model)
9. [Telemetry Schema & Feature Extraction](#telemetry-schema--feature-extraction)
10. [API Reference](#api-reference)
11. [Browser Support](#browser-support)
12. [Accessibility](#accessibility)
13. [Testing & Attack Verification](#testing--attack-verification)
14. [Limitations](#limitations)

---

## What is TrustPulse AI?

Traditional web application security establishes trust primarily at login. Once authenticated, a session cookie or bearer token is granted, leaving applications blind to post-login session hijacking, adversary-in-the-middle (AiTM) proxy attacks, credential sharing, and unauthorized remote access.

**TrustPulse AI** is a B2B continuous-session-security platform that provides an ambient, privacy-preserving layer of behavioral verification throughout the life of an authenticated session.

`@trustpulse/sdk` is the official browser client library. It observes non-sensitive behavioral interaction signals (keystroke dynamics, mouse kinematics, touch cadence), extracts statistical features locally on the client, and securely transmits versioned telemetry packets to the TrustPulse backend risk engine.

---

## Why TrustPulse Exists

* **Zero Keystroke / Zero Character Capture**: Passwords, OTP codes, credit cards, and form inputs are NEVER recorded or transmitted.
* **Local Feature Extraction**: The browser extracts aggregate mathematical features (dwell/flight standard deviations, velocities, accelerations) rather than streaming raw interaction trajectories.
* **Separation of Concerns (Detection ≠ Decision ≠ Explanation)**: The SDK is strictly a telemetry collector. It **never** decides whether a user is malicious, **never** computes final risk scores, and **never** directly blocks transactions. The backend deterministic policy engine is the sole security authority.
* **Zero Runtime Dependencies**: Lightweight, tree-shakeable, and self-contained to avoid software supply chain vulnerabilities.

---

## Architecture Overview

```text
┌────────────────────────────────────────────────────────┐
│                   CUSTOMER WEB APP                     │
│  User logs in -> App creates authenticated session     │
│  App initializes TrustPulse SDK with sessionId         │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│                   TRUSTPULSE SDK                       │
│  ├─ SessionManager (binds instance ID & sequence num)  │
│  ├─ PrivacyManager (filters sensitive/password inputs) │
│  ├─ Collectors (Typing, Mouse, Click, Scroll, Touch)   │
│  ├─ FeatureExtractors (statistical aggregation)        │
│  ├─ Bounded Telemetry Queue (FIFO drop policy)         │
│  └─ TelemetryClient (HTTPS, exponential backoff)       │
└───────────────────────────┬────────────────────────────┘
                            │ HTTPS (POST /v1/telemetry)
                            ▼
┌────────────────────────────────────────────────────────┐
│                 TRUSTPULSE BACKEND                     │
│  ├─ Telemetry Validation & Sequence Integrity          │
│  ├─ Behavioral Engine (Candidate vs Trusted Baseline)  │
│  ├─ Device & Network Intelligence                      │
│  ├─ Action Risk Engine (High-risk action evaluation)   │
│  └─ Deterministic Policy Engine (ALLOW/STEP_UP/BLOCK)  │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
                 ALLOW / STEP_UP / BLOCK
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│                   CUSTOMER WEB APP                     │
│  Enforces step-up auth or terminates session           │
└────────────────────────────────────────────────────────┘
```

---

## Installation

```bash
npm install @trustpulse/sdk
```

Or using Yarn:

```bash
yarn add @trustpulse/sdk
```

---

## Quick Start

```typescript
import { TrustPulse } from "@trustpulse/sdk";

// 1. Initialize the SDK after the user authenticates
const trustpulse = new TrustPulse({
  apiUrl: "https://api.trustpulse.security",
  publicKey: "pk_live_your_customer_key",
  sessionId: "session_user_authenticated_9921",
  telemetryIntervalMs: 3000,
});

// 2. Start continuous observation
trustpulse.start();

// 3. Optional: Pause or resume during background idle states
// trustpulse.pause();
// trustpulse.resume();

// 4. Clean teardown upon user logout
window.addEventListener("logout", () => {
  trustpulse.destroy();
});
```

---

## Configuration Reference

```typescript
interface TrustPulseConfig {
  /** TrustPulse backend ingestion gateway (must use HTTPS in production) */
  apiUrl: string;

  /** Non-secret customer public application key */
  publicKey: string;

  /** Host application's authenticated session identifier */
  sessionId: string;

  /** Background telemetry dispatch interval in ms (1000 - 60000). Default: 3000 */
  telemetryIntervalMs?: number;

  /** Maximum buffered telemetry items before dropping oldest. Default: 500 */
  maxQueueSize?: number;

  /** Number of packets per HTTPS transmission. Default: 10 */
  batchSize?: number;

  /** Maximum retry attempts on transient 5xx/network errors. Default: 3 */
  maxRetries?: number;

  /** Individual collector feature toggles (all default to true) */
  enableTypingSignals?: boolean;
  enableMouseSignals?: boolean;
  enableClickSignals?: boolean;
  enableScrollSignals?: boolean;
  enableTouchSignals?: boolean;
  enableDeviceSignals?: boolean;

  /** "standard" (default) or "strict" */
  privacyMode?: "standard" | "strict";

  /** Enable console diagnostics (default: false). Never logs sensitive secrets */
  debug?: boolean;

  /** Additional CSS selectors for custom elements to ignore */
  ignoredSelectors?: string[];
}
```

---

## Privacy Architecture & Zero-Content Guarantee

TrustPulse enforces strict privacy boundaries by design:

1. **TypingCollector**: Only captures high-resolution timestamp deltas (`performance.now()`) for key dwell and flight durations. **It never accesses `event.key`, `event.code`, or text input values.**
2. **Automatic Input Exclusion**: The SDK automatically stops capturing signals on:
   - `input[type="password"]`
   - `input[autocomplete*="password"]`
   - `input[autocomplete="one-time-code"]` (OTP/MFA)
   - `input[autocomplete*="cc-"]` (Credit card fields)
   - Elements with names/IDs containing `pin`, `ssn`, `cvv`, `secret`, `otp`, `token`
3. **Explicit Application Ignore**: Any element or subtree marked with `data-trustpulse-ignore` is completely bypassed:
   ```html
   <input type="text" data-trustpulse-ignore placeholder="Sensitive customer field" />
   ```
4. **Sanitized Structural Metadata**: Interaction targets (e.g. click context) only record generic tag names (e.g. `button`), never inner text, transaction amounts, or personal data.

---

## Security Model

* **Client is Untrusted**: Browser JavaScript runs in an untrusted environment. Telemetry packets include monotonic sequence numbers, instance UUIDs, and integrity checksums so the backend can detect replayed, tampered, or spoofed packets.
* **No Client-Side Secrets**: Never embed private keys or backend service credentials in client code. The `publicKey` is an identifier, not a secret.
* **Bounded In-Memory Buffer**: Prevents denial-of-service memory flooding by enforcing a strict capacity limit and dropping oldest items if the queue fills.
* **Graceful Degradation**: If the TrustPulse ingestion gateway is unreachable, the SDK gracefully limits retries, buffers up to capacity, and never blocks customer application operations.

---

## Telemetry Schema & Feature Extraction

Each packet transmitted to `/v1/telemetry` adheres to:

```typescript
interface TelemetryPacket {
  sessionId: string;
  sdkInstanceId: string;
  eventId: string;
  sequenceNumber: number;
  timestamp: number;
  schemaVersion: "1.0.0";
  sdkVersion: "1.0.0";
  eventType: "behavioral_batch" | "session_start" | "session_stop" | "heartbeat";
  features: {
    feature_schema_version: "1.0.0";
    typing?: {
      sampleCount: number;
      meanDwellTime: number;
      dwellStdDev: number;
      meanFlightTime: number;
      flightStdDev: number;
      typingSpeed: number;
      pauseRate: number;
    };
    mouse?: {
      sampleCount: number;
      meanVelocity: number;
      velocityStdDev: number;
      meanAcceleration: number;
      directionChangeRate: number;
      movementDuration: number;
      totalDistance: number;
    };
    click?: {
      clickCount: number;
      doubleClickCount: number;
      meanInterval: number;
      intervalStdDev: number;
      clickFrequency: number;
    };
    scroll?: {
      scrollEventCount: number;
      totalDistance: number;
      meanVelocity: number;
      meanPauseDuration: number;
    };
    device?: DeviceContext;
  };
  integrity: string;
}
```

---

## API Reference

### `class TrustPulse`

* `constructor(config: TrustPulseConfig)`: Initializes and validates configuration.
* `start(): void`: Begins event listening and background telemetry dispatch.
* `stop(): void`: Stops observers and clears scheduled intervals.
* `pause(): void`: Temporarily pauses signal observation without destroying state.
* `resume(): void`: Resumes active observation.
* `flush(): Promise<void>`: Immediately extracts features and dispatches buffered telemetry.
* `destroy(): void`: Completely tears down observers, flushes final beacon, and clears buffer.
* `getStatus(): SDKStatus`: Returns `"uninitialized" | "ready" | "running" | "paused" | "stopped" | "destroyed"`.
* `updateSession(newSessionId: string): void`: Updates session identifier upon token refresh.
* `static readonly version: string`: SDK semver string.

---

## Browser Support

Designed for and tested on all modern Evergreen browsers:
- Google Chrome 90+
- Microsoft Edge 90+
- Mozilla Firefox 88+
- Apple Safari 14+
- iOS Safari & Android Chrome

Gracefully falls back when optional APIs (PointerEvent, TouchEvent, requestIdleCallback, sendBeacon) are unavailable.

---

## Accessibility

TrustPulse recognizes that users have diverse interaction methods:
- Keyboard-only navigation
- Screen readers & assistive technology
- Alternative input devices (trackballs, eye-tracking, switch controls)

The SDK collects evidence across multiple modalities. Under TrustPulse architecture, the backend never treats the absence of a mouse or unusual keyboard timing as definitive proof of an attack.

---

## Testing & Attack Verification

The SDK contains a comprehensive test suite including 8 dedicated security attack scenarios:

```bash
cd trustpulse/sdk
npm test
```

### Verified Attack Scenarios:
* **Attack 1 (Password Capture)**: Verifies password fields are excluded and zero passwords enter telemetry.
* **Attack 2 (OTP Capture)**: Verifies `one-time-code` and MFA inputs are completely ignored.
* **Attack 3 (Raw Keystroke Capture)**: Verifies zero character/key representations exist in samples or packets.
* **Attack 4 (Telemetry Flooding)**: Verifies bounded queue prevents memory exhaustion under 1,000+ rapid events.
* **Attack 5 (Replay Detection)**: Verifies unique UUID event IDs and monotonic sequence numbers on every packet.
* **Attack 6 (Tampered Configuration)**: Verifies rejection of non-HTTPS endpoints and empty keys.
* **Attack 7 (Network Failure Resilience)**: Verifies non-blocking operation during backend outages.
* **Attack 8 (Untrusted Client Boundary)**: Verifies absence of client-side decision methods, private keys, or authoritative trust scores.

---

## Limitations

1. **Client is Untrusted**: While the SDK provides integrity checksums and sequence numbers, it cannot mathematically prevent a compromised browser with root/debugger access from fabricating synthetic events. Verification is always probabilistic and authoritative on the backend.
2. **Not an Authentication System**: TrustPulse does not authenticate users; it protects active sessions created by the host application.
3. **No Direct Bank Integration**: The SDK does not and must not connect to banking databases or core banking mainframes directly.

---

## License

Apache License 2.0. Copyright (c) 2026 TrustPulse AI.
