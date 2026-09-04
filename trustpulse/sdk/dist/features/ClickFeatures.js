/**
 * @trustpulse/sdk - Click Dynamics Feature Extraction
 *
 * Computes click cadences, intervals, and burst dynamics.
 */
import { MathUtils } from "../utils/Math";
export class ClickFeatureExtractor {
    static extract(samples, windowDurationMs = 3000) {
        if (!samples || samples.length === 0) {
            return {
                clickCount: 0,
                doubleClickCount: 0,
                meanInterval: 0,
                intervalStdDev: 0,
                clickFrequency: 0,
            };
        }
        const intervals = samples.map((s) => s.intervalFromLastClick).filter((i) => i > 0);
        const doubleClicks = samples.filter((s) => s.isDoubleClick).length;
        const meanInt = MathUtils.mean(intervals);
        const intStd = MathUtils.stdDev(intervals, meanInt);
        const minutes = Math.max(0.016, windowDurationMs / 60000);
        const frequency = samples.length / minutes;
        return {
            clickCount: samples.length,
            doubleClickCount: doubleClicks,
            meanInterval: MathUtils.safeNumber(meanInt, 0, 60000),
            intervalStdDev: MathUtils.safeNumber(intStd, 0, 60000),
            clickFrequency: MathUtils.safeNumber(frequency, 0, 1000),
        };
    }
}
//# sourceMappingURL=ClickFeatures.js.map