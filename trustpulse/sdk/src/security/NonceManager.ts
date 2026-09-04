/**
 * @trustpulse/sdk - Nonce and Sequence Manager
 *
 * Manages strictly monotonic sequence numbering and random nonces.
 * Sequence numbers allow backend telemetry validation to detect replayed,
 * dropped, or out-of-order packets.
 */

import { EventIdGenerator } from "./EventId";

export class NonceManager {
  private currentSequence = 0;

  /**
   * Returns the next monotonically incremented sequence number.
   */
  public nextSequence(): number {
    this.currentSequence += 1;
    return this.currentSequence;
  }

  /**
   * Returns the current sequence number without incrementing.
   */
  public getSequence(): number {
    return this.currentSequence;
  }

  /**
   * Generates a cryptographic or high-entropy nonce string.
   */
  public generateNonce(): string {
    return EventIdGenerator.generate().replace(/-/g, "");
  }

  /**
   * Resets sequence counter (used during session renewal or re-initialization).
   */
  public reset(): void {
    this.currentSequence = 0;
  }
}
