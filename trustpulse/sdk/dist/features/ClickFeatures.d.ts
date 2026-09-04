/**
 * @trustpulse/sdk - Click Dynamics Feature Extraction
 *
 * Computes click cadences, intervals, and burst dynamics.
 */
import type { ClickSample } from "../collectors/ClickCollector";
import type { ClickFeatures } from "./FeatureTypes";
export declare class ClickFeatureExtractor {
    static extract(samples: ClickSample[], windowDurationMs?: number): ClickFeatures;
}
//# sourceMappingURL=ClickFeatures.d.ts.map