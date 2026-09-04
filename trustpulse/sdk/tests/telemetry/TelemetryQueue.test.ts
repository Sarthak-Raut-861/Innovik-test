import { describe, it, expect } from "vitest";
import { TelemetryQueue } from "../../src/telemetry/TelemetryQueue";
import type { TelemetryPacket } from "../../src/telemetry/TelemetryTypes";

describe("TelemetryQueue (Bounded In-Memory Buffer)", () => {
  const createMockPacket = (id: string, seq: number): TelemetryPacket => ({
    sessionId: "test-session",
    sdkInstanceId: "inst-1",
    eventId: id,
    sequenceNumber: seq,
    timestamp: Date.now(),
    schemaVersion: "1.0.0",
    sdkVersion: "1.0.0",
    eventType: "behavioral_batch",
    features: { feature_schema_version: "1.0.0" },
  });

  it("enqueues and dequeues batches properly", () => {
    const queue = new TelemetryQueue(10);
    queue.enqueue(createMockPacket("evt-1", 1));
    queue.enqueue(createMockPacket("evt-2", 2));

    expect(queue.size()).toBe(2);

    const batch = queue.dequeueBatch(1);
    expect(batch.length).toBe(1);
    expect(batch[0]!.eventId).toBe("evt-1");
    expect(queue.size()).toBe(1);
  });

  it("prevents duplicate event insertion", () => {
    const queue = new TelemetryQueue(10);
    const packet = createMockPacket("evt-dup", 1);
    expect(queue.enqueue(packet)).toBe(true);
    expect(queue.enqueue(packet)).toBe(false);
    expect(queue.size()).toBe(1);
  });

  it("enforces capacity bound and drops oldest packets (FIFO drop)", () => {
    const queue = new TelemetryQueue(5);
    for (let i = 1; i <= 8; i++) {
      queue.enqueue(createMockPacket(`evt-${i}`, i));
    }

    expect(queue.size()).toBe(5);
    expect(queue.getDroppedCount()).toBe(3);

    // Oldest items (1, 2, 3) were dropped; head should now be evt-4
    const batch = queue.dequeueBatch(5);
    expect(batch[0]!.eventId).toBe("evt-4");
  });

  it("requeues failed packets at the front while respecting capacity", () => {
    const queue = new TelemetryQueue(5);
    queue.enqueue(createMockPacket("evt-3", 3));
    queue.enqueue(createMockPacket("evt-4", 4));

    const failed = [createMockPacket("evt-1", 1), createMockPacket("evt-2", 2)];
    queue.requeue(failed);

    expect(queue.size()).toBe(4);
    const batch = queue.dequeueBatch(2);
    expect(batch[0]!.eventId).toBe("evt-1");
    expect(batch[1]!.eventId).toBe("evt-2");
  });
});
