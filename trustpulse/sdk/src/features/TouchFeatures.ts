/**
 * @trustpulse/sdk - Touch Dynamics Feature Extraction
 *
 * Extracts aggregate gesture statistics, mean swipe velocity, and gesture distributions.
 */

import type { TouchGestureSample } from "../collectors/TouchCollector";
import type { TouchFeatures } from "./FeatureTypes";
import { MathUtils } from "../utils/Math";

export class TouchFeatureExtractor {
  public static extract(samples: TouchGestureSample[]): TouchFeatures {
    if (!samples || samples.length === 0) {
      return {
        touchCount: 0,
        meanDuration: 0,
        meanVelocity: 0,
        directionDistribution: { tap: 0, up: 0, down: 0, left: 0, right: 0 },
      };
    }

    const durations = samples.map((s) => s.duration);
    const velocities = samples.map((s) => s.velocity);

    const dist = { tap: 0, up: 0, down: 0, left: 0, right: 0 };
    for (const sample of samples) {
      dist[sample.direction] += 1;
    }

    return {
      touchCount: samples.length,
      meanDuration: MathUtils.safeNumber(MathUtils.mean(durations), 0, 10000),
      meanVelocity: MathUtils.safeNumber(MathUtils.mean(velocities), 0, 100000),
      directionDistribution: dist,
    };
  }
}
