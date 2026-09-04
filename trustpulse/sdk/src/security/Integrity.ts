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

export class IntegrityManager {
  /**
   * Generates a 32-bit FNV-1a checksum of the payload string as a fast, dependency-free hash.
   */
  public static computeChecksum(data: string): string {
    let hash = 0x811c9dc5;
    for (let i = 0; i < data.length; i++) {
      hash ^= data.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193);
    }
    return (hash >>> 0).toString(16).padStart(8, "0");
  }

  /**
   * Calculates async SHA-256 hex digest if SubtleCrypto is available.
   */
  public static async computeSha256(data: string): Promise<string> {
    if (typeof crypto !== "undefined" && crypto.subtle && typeof crypto.subtle.digest === "function") {
      try {
        const encoder = new TextEncoder();
        const buffer = await crypto.subtle.digest("SHA-256", encoder.encode(data));
        const hashArray = Array.from(new Uint8Array(buffer));
        return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
      } catch {
        // Fall back to FNV-1a checksum
      }
    }
    return IntegrityManager.computeChecksum(data);
  }
}
