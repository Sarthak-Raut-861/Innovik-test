/**
 * @trustpulse/sdk - Integrity Utilities
 *
 * Computes payload checksums to protect against transmission corruption.
 *
 * NOTE ON SECURITY BOUNDARY:
 * In accordance with Core Rule 1 ("Client is untrusted"), this checksum
 * is a telemetry integrity envelope for the backend to detect packet truncation,
 * network bitflips, or proxy alteration. It does NOT claim to turn a compromised
 * browser into a trusted endpoint.
 */
export declare class IntegrityManager {
    /**
     * Generates a 32-bit FNV-1a checksum of the payload string as a fast, dependency-free hash.
     */
    static computeChecksum(data: string): string;
    /**
     * Calculates async SHA-256 hex digest if SubtleCrypto is available.
     */
    static computeSha256(data: string): Promise<string>;
}
//# sourceMappingURL=Integrity.d.ts.map