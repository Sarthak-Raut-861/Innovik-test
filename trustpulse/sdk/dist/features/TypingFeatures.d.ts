/**
 * @trustpulse/sdk - Typing Feature Extraction
 *
 * Transforms privacy-safe keystroke timing intervals into aggregate statistical features.
 * Guarantees bounded outputs and NaN/Infinity defense.
 */
import type { KeystrokeTimingSample } from "../collectors/TypingCollector";
import type { TypingFeatures } from "./FeatureTypes";
export declare class TypingFeatureExtractor {
    static extract(samples: KeystrokeTimingSample[], windowDurationMs?: number): TypingFeatures;
}
//# sourceMappingURL=TypingFeatures.d.ts.map