/**
 * @trustpulse/sdk - Mathematical and Statistical Utilities
 *
 * Provides safe numerical computations, bounds checking, and statistical aggregation.
 * Guarantees that no NaN or Infinity values ever propagate to telemetry payloads.
 */
export class MathUtils {
    /**
     * Sanitizes a number, guaranteeing it is finite and within bounded range.
     */
    static safeNumber(val, min = -1e9, max = 1e9, fallback = 0, precision = 4) {
        if (typeof val !== "number" || Number.isNaN(val) || !Number.isFinite(val)) {
            return fallback;
        }
        const clamped = Math.max(min, Math.min(max, val));
        const factor = 10 ** precision;
        return Math.round(clamped * factor) / factor;
    }
    /**
     * Computes the arithmetic mean of an array of numbers.
     */
    static mean(values) {
        if (!values || values.length === 0)
            return 0;
        const sum = values.reduce((acc, curr) => acc + (Number.isFinite(curr) ? curr : 0), 0);
        return MathUtils.safeNumber(sum / values.length);
    }
    /**
     * Computes population variance of an array of numbers.
     */
    static variance(values, meanVal) {
        if (!values || values.length < 2)
            return 0;
        const m = meanVal !== undefined ? meanVal : MathUtils.mean(values);
        const sumSqDiff = values.reduce((acc, curr) => {
            if (!Number.isFinite(curr))
                return acc;
            const diff = curr - m;
            return acc + diff * diff;
        }, 0);
        return MathUtils.safeNumber(sumSqDiff / values.length);
    }
    /**
     * Computes population standard deviation.
     */
    static stdDev(values, meanVal) {
        return MathUtils.safeNumber(Math.sqrt(MathUtils.variance(values, meanVal)));
    }
    /**
     * Computes Euclidean distance between two 2D points.
     */
    static euclideanDistance(x1, y1, x2, y2) {
        const dx = x2 - x1;
        const dy = y2 - y1;
        return MathUtils.safeNumber(Math.sqrt(dx * dx + dy * dy));
    }
    /**
     * Computes angular direction change between two movement vectors in radians (0 to PI).
     */
    static angleDelta(dx1, dy1, dx2, dy2) {
        const mag1 = Math.sqrt(dx1 * dx1 + dy1 * dy1);
        const mag2 = Math.sqrt(dx2 * dx2 + dy2 * dy2);
        if (mag1 === 0 || mag2 === 0)
            return 0;
        const dot = dx1 * dx2 + dy1 * dy2;
        const cosTheta = Math.max(-1, Math.min(1, dot / (mag1 * mag2)));
        return MathUtils.safeNumber(Math.acos(cosTheta));
    }
    /**
     * Clamps a value to the specified range.
     */
    static clamp(val, min, max) {
        if (Number.isNaN(val))
            return min;
        return Math.max(min, Math.min(max, val));
    }
}
//# sourceMappingURL=Math.js.map