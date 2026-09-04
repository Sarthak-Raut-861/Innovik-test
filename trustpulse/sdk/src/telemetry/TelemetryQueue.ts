/**
 * @trustpulse/sdk - Bounded In-Memory Telemetry Queue
 *
 * Implements a bounded buffer with FIFO eviction to strictly cap memory usage.
 * Supports batch extraction and requeuing for retry handling.
 */

import type { TelemetryPacket } from "./TelemetryTypes";

export class TelemetryQueue {
  private queue: TelemetryPacket[] = [];
  private readonly maxSize: number;
  private droppedEventsCount = 0;
  private seenEventIds = new Set<string>();

  constructor(maxSize = 500) {
    this.maxSize = Math.max(1, maxSize);
  }

  public enqueue(packet: TelemetryPacket): boolean {
    // Duplicate prevention
    if (this.seenEventIds.has(packet.eventId)) {
      return false;
    }

    // FIFO eviction when buffer capacity is reached
    if (this.queue.length >= this.maxSize) {
      const dropped = this.queue.shift();
      if (dropped) {
        this.seenEventIds.delete(dropped.eventId);
        this.droppedEventsCount += 1;
      }
    }

    this.queue.push(packet);
    this.seenEventIds.add(packet.eventId);

    // Limit seenEventIds set size to prevent memory leaks over long sessions
    if (this.seenEventIds.size > this.maxSize * 2) {
      const activeIds = new Set(this.queue.map((p) => p.eventId));
      this.seenEventIds = activeIds;
    }

    return true;
  }

  public dequeueBatch(batchSize: number): TelemetryPacket[] {
    const count = Math.min(batchSize, this.queue.length);
    const batch = this.queue.splice(0, count);
    return batch;
  }

  /**
   * Puts unacknowledged packets back at the front of the queue following a transient transport failure.
   */
  public requeue(packets: TelemetryPacket[]): void {
    if (!packets || packets.length === 0) return;

    // Filter out packets that exceed maxSize
    const combined = [...packets, ...this.queue];
    while (combined.length > this.maxSize) {
      combined.pop();
      this.droppedEventsCount += 1;
    }
    this.queue = combined;
  }

  public size(): number {
    return this.queue.length;
  }

  public isEmpty(): boolean {
    return this.queue.length === 0;
  }

  public getDroppedCount(): number {
    return this.droppedEventsCount;
  }

  public clear(): void {
    this.queue = [];
    this.seenEventIds.clear();
    this.droppedEventsCount = 0;
  }
}
