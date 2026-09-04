/**
 * @trustpulse/sdk - Telemetry Schemas & Types
 *
 * Strongly typed telemetry packet definitions.
 * STRICT PROHIBITION: Never includes passwords, raw keystrokes, form text,
 * authorization secrets, cookies, or localStorage contents.
 */
import type { ExtractedFeaturePayload } from "../features/FeatureTypes";
export declare const TELEMETRY_SCHEMA_VERSION = "1.0.0";
export declare const SDK_VERSION = "1.0.0";
export interface TelemetryPacketMetadata {
    pageContext?: string;
    pageVisibility?: string;
}
export interface TelemetryPacket {
    sessionId: string;
    sdkInstanceId: string;
    eventId: string;
    sequenceNumber: number;
    timestamp: number;
    schemaVersion: string;
    sdkVersion: string;
    eventType: "behavioral_batch" | "session_start" | "session_stop" | "heartbeat";
    features: ExtractedFeaturePayload;
    metadata?: TelemetryPacketMetadata;
    integrity?: string;
}
export interface TelemetryBatch {
    batchId: string;
    sentAt: number;
    packets: TelemetryPacket[];
}
//# sourceMappingURL=TelemetryTypes.d.ts.map