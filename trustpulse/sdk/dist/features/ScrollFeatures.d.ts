/**
 * @trustpulse/sdk - Scroll Dynamics Feature Extraction
 *
 * Extracts aggregate scroll velocities and pause characteristics.
 */
import type { ScrollSample } from "../collectors/ScrollCollector";
import type { ScrollFeatures } from "./FeatureTypes";
export declare class ScrollFeatureExtractor {
    static extract(samples: ScrollSample[]): ScrollFeatures;
}
//# sourceMappingURL=ScrollFeatures.d.ts.map