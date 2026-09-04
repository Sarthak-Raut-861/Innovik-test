/**
 * @trustpulse/sdk - Transport Types
 */

import type { TelemetryBatch } from "../telemetry/TelemetryTypes";

export interface TransportResponse {
  success: boolean;
  status: number;
  message?: string;
  retryable: boolean;
}

export interface ITelemetryClient {
  sendBatch(batch: TelemetryBatch): Promise<TransportResponse>;
  sendBeacon(batch: TelemetryBatch): boolean;
}
