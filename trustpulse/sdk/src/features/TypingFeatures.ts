/**
 * @trustpulse/sdk - Typing Feature Extraction
 *
 * Transforms privacy-safe keystroke timing intervals into aggregate statistical features.
 * Guarantees bounded outputs and NaN/Infinity defense.
 */

import type { KeystrokeTimingSample } from "../collectors/TypingCollector";
import type { TypingFeatures } from "./FeatureTypes";
import { MathUtils } from "../utils/Math";

export class TypingFeatureExtractor {
  public static extract(samples: KeystrokeTimingSample[], windowDurationMs = 3000): TypingFeatures {
    if (!samples || samples.length === 0) {
      return {
        sampleCount: 0,
        meanDwellTime: 0,
        dwellStdDev: 0,
        meanFlightTime: 0,
        flightStdDev: 0,
        typingSpeed: 0,
        pauseRate: 0,
      };
    }

    const dwellTimes = samples.map((s) => s.dwellTime);
    const flightTimes = samples.map((s) => s.flightTime).filter((f) => f > 0);

    const meanDwell = MathUtils.mean(dwellTimes);
    const dwellStd = MathUtils.stdDev(dwellTimes, meanDwell);

    const meanFlight = MathUtils.mean(flightTimes);
    const flightStd = MathUtils.stdDev(flightTimes, meanFlight);

    // Typing speed: keystrokes per second across observation window
    const durationSeconds = Math.max(1, windowDurationMs / 1000);
    const typingSpeed = MathUtils.safeNumber(samples.length / durationSeconds, 0, 50);

    // Pauses: count of flight times exceeding 1000ms
    const pauseCount = flightTimes.filter((f) => f > 1000).length;
    const pauseRate = MathUtils.safeNumber(pauseCount / samples.length, 0, 1);

    return {
      sampleCount: samples.length,
      meanDwellTime: MathUtils.safeNumber(meanDwell, 0, 5000),
      dwellStdDev: MathUtils.safeNumber(dwellStd, 0, 5000),
      meanFlightTime: MathUtils.safeNumber(meanFlight, 0, 5000),
      flightStdDev: MathUtils.safeNumber(flightStd, 0, 5000),
      typingSpeed,
      pauseRate,
    };
  }
}
