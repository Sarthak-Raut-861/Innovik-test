/**
 * @trustpulse/sdk - Privacy Types
 */
import type { PrivacyMode } from "../config/types";
export interface PrivacyConfig {
    collectTyping: boolean;
    collectMouse: boolean;
    collectClick: boolean;
    collectScroll: boolean;
    collectTouch: boolean;
    collectDevice: boolean;
    localFeatureExtraction: boolean;
    privacyMode: PrivacyMode;
    ignoredSelectors: string[];
}
//# sourceMappingURL=PrivacyTypes.d.ts.map