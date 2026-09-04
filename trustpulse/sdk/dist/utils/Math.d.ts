/**
 * @trustpulse/sdk - Mathematical and Statistical Utilities
 *
 * Provides safe numerical computations, bounds checking, and statistical aggregation.
 * Guarantees that no NaN or Infinity values ever propagate to telemetry payloads.
 */
export declare class MathUtils {
    /**
     * Sanitizes a number, guaranteeing it is finite and within bounded range.
     */
    static safeNumber(val: number, min?: number, max?: number, fallback?: number, precision?: number): number;
    /**
     * Computes the arithmetic mean of an array of numbers.
     */
    static mean(values: number[]): number;
    /**
     * Computes population variance of an array of numbers.
     */
    static variance(values: number[], meanVal?: number): number;
    /**
     * Computes population standard deviation.
     */
    static stdDev(values: number[], meanVal?: number): number;
    /**
     * Computes Euclidean distance between two 2D points.
     */
    static euclideanDistance(x1: number, y1: number, x2: number, y2: number): number;
    /**
     * Computes angular direction change between two movement vectors in radians (0 to PI).
     */
    static angleDelta(dx1: number, dy1: number, dx2: number, dy2: number): number;
    /**
     * Clamps a value to the specified range.
     */
    static clamp(val: number, min: number, max: number): number;
}
//# sourceMappingURL=Math.d.ts.map