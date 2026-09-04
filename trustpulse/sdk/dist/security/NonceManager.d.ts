/**
 * @trustpulse/sdk - Nonce and Sequence Manager
 *
 * Manages strictly monotonic sequence numbering and random nonces.
 * Sequence numbers allow backend telemetry validation to detect replayed,
 * dropped, or out-of-order packets.
 */
export declare class NonceManager {
    private currentSequence;
    /**
     * Returns the next monotonically incremented sequence number.
     */
    nextSequence(): number;
    /**
     * Returns the current sequence number without incrementing.
     */
    getSequence(): number;
    /**
     * Generates a cryptographic or high-entropy nonce string.
     */
    generateNonce(): string;
    /**
     * Resets sequence counter (used during session renewal or re-initialization).
     */
    reset(): void;
}
//# sourceMappingURL=NonceManager.d.ts.map