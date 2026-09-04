/**
 * @trustpulse/sdk - Scroll Dynamics Feature Extraction
 *
 * Extracts aggregate scroll velocities and pause characteristics.
 */

import type { ScrollSample } from "../collectors/ScrollCollector";
import type { ScrollFeatures } from "./FeatureTypes";
import { MathUtils } from "../utils/Math";

export class ScrollFeatureExtractor {
  public static extract(samples: ScrollSample[]): ScrollFeatures {
    if (!samples || samples.length === 0) {
      return {
        scrollEventCount: 0,
        totalDistance: 0,
        meanVelocity: 0,
        meanPauseDuration: 0,
      };
    }

    let totalDist = 0;
    const velocities: number[] = [];
    const pauses: number[] = [];

    for (const sample of samples) {
      totalDist += sample.deltaY;
      if (sample.duration > 0) {
        const v = (sample.deltaY / sample.duration) * 1000; // px/sec
        velocities.push(v);
        if (sample.duration > 500) {
          pauses.push(sample.duration);
        }
      }
    }

    const meanV = MathUtils.mean(velocities);
    const meanPause = MathUtils.mean(pauses);

    return {
      scrollEventCount: samples.length,
      totalDistance: MathUtils.safeNumber(totalDist, 0, 10000000),
      meanVelocity: MathUtils.safeNumber(meanV, 0, 100000),
      meanPauseDuration: MathUtils.safeNumber(meanPause, 0, 60000),
    };
  }
}
