/**
 * @trustpulse/sdk - Mouse Kinematic Feature Extraction
 *
 * Derives statistical kinematics (velocities, accelerations, angular curvature)
 * from locally sampled trajectory points. Never transmits coordinate points.
 */
import type { MousePointSample } from "../collectors/MouseCollector";
import type { MouseFeatures } from "./FeatureTypes";
export declare class MouseFeatureExtractor {
    static extract(samples: MousePointSample[]): MouseFeatures;
}
//# sourceMappingURL=MouseFeatures.d.ts.map