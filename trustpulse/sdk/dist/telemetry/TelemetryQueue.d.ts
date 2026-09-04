/**
 * @trustpulse/sdk - Bounded In-Memory Telemetry Queue
 *
 * Implements a bounded buffer with FIFO eviction to strictly cap memory usage.
 * Supports batch extraction and requeuing for retry handling.
 */
import type { TelemetryPacket } from "./TelemetryTypes";
export declare class TelemetryQueue {
    private queue;
    private readonly maxSize;
    private droppedEventsCount;
    private seenEventIds;
    constructor(maxSize?: number);
    enqueue(packet: TelemetryPacket): boolean;
    dequeueBatch(batchSize: number): TelemetryPacket[];
    /**
     * Puts unacknowledged packets back at the front of the queue following a transient transport failure.
     */
    requeue(packets: TelemetryPacket[]): void;
    size(): number;
    isEmpty(): boolean;
    getDroppedCount(): number;
    clear(): void;
}
//# sourceMappingURL=TelemetryQueue.d.ts.map