/**
 * @trustpulse/sdk - Touch Dynamics Feature Extraction
 *
 * Extracts aggregate gesture statistics, mean swipe velocity, and gesture distributions.
 */
import type { TouchGestureSample } from "../collectors/TouchCollector";
import type { TouchFeatures } from "./FeatureTypes";
export declare class TouchFeatureExtractor {
    static extract(samples: TouchGestureSample[]): TouchFeatures;
}
//# sourceMappingURL=TouchFeatures.d.ts.map