# TrustPulse AI — Security Model & Non-Negotiable Invariants

## Core Invariants

1. **Client is Untrusted**: Browser JavaScript runs in an adversarial environment. The SDK is purely an evidence gathering mechanism.
2. **Backend is the Sole Security Authority**: No security decisions are ever rendered in the browser.
3. **Behavior is Evidence, Not Identity**: Behavioral biometrics provide probabilistic continuous session confidence, not absolute identity.
4. **Zero-Content Privacy Guarantee**:
   - Zero character strings, raw keys, or text inputs are ever collected.
   - Password fields (`type="password"`, `autocomplete*="password"`) are strictly blacklisted.
   - OTP fields (`autocomplete="one-time-code"`) are strictly blacklisted.
   - Customer-ignored inputs (`[data-trustpulse-ignore]`) are strictly bypassed.
5. **Replay & Tamper Detection**:
   - Every packet contains a UUID v4 `eventId` and monotonically increasing `sequenceNumber`.
   - Packets include integrity checksums computed over feature payloads.
6. **Bounded Memory & Resiliency**:
   - The in-memory buffer enforces a hard maximum queue size with FIFO eviction to prevent DoS memory exhaustion.
   - Transient network failures trigger bounded exponential backoff with randomized jitter.
   - SDK operations are strictly non-blocking: backend downtime never degrades host application functionality.
