/**
 * @trustpulse/sdk - Nonce and Sequence Manager
 *
 * Manages strictly monotonic sequence numbering and random nonces.
 * Sequence numbers allow backend telemetry validation to detect replayed,
 * dropped, or out-of-order packets.
 */
import { EventIdGenerator } from "./EventId";
export class NonceManager {
    currentSequence = 0;
    /**
     * Returns the next monotonically incremented sequence number.
     */
    nextSequence() {
        this.currentSequence += 1;
        return this.currentSequence;
    }
    /**
     * Returns the current sequence number without incrementing.
     */
    getSequence() {
        return this.currentSequence;
    }
    /**
     * Generates a cryptographic or high-entropy nonce string.
     */
    generateNonce() {
        return EventIdGenerator.generate().replace(/-/g, "");
    }
    /**
     * Resets sequence counter (used during session renewal or re-initialization).
     */
    reset() {
        this.currentSequence = 0;
    }
}
//# sourceMappingURL=NonceManager.js.map