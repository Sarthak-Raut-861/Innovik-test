/**
 * @trustpulse/sdk - Bounded In-Memory Telemetry Queue
 *
 * Implements a bounded buffer with FIFO eviction to strictly cap memory usage.
 * Supports batch extraction and requeuing for retry handling.
 */
export class TelemetryQueue {
    queue = [];
    maxSize;
    droppedEventsCount = 0;
    seenEventIds = new Set();
    constructor(maxSize = 500) {
        this.maxSize = Math.max(1, maxSize);
    }
    enqueue(packet) {
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
    dequeueBatch(batchSize) {
        const count = Math.min(batchSize, this.queue.length);
        const batch = this.queue.splice(0, count);
        return batch;
    }
    /**
     * Puts unacknowledged packets back at the front of the queue following a transient transport failure.
     */
    requeue(packets) {
        if (!packets || packets.length === 0)
            return;
        // Filter out packets that exceed maxSize
        const combined = [...packets, ...this.queue];
        while (combined.length > this.maxSize) {
            combined.pop();
            this.droppedEventsCount += 1;
        }
        this.queue = combined;
    }
    size() {
        return this.queue.length;
    }
    isEmpty() {
        return this.queue.length === 0;
    }
    getDroppedCount() {
        return this.droppedEventsCount;
    }
    clear() {
        this.queue = [];
        this.seenEventIds.clear();
        this.droppedEventsCount = 0;
    }
}
//# sourceMappingURL=TelemetryQueue.js.map