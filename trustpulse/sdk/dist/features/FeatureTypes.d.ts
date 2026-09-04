/**
 * @trustpulse/sdk - Feature Schemas & Types
 *
 * All extracted features are strictly numerical, normalized where appropriate,
 * bounded to prevent NaN/Infinity, and tagged with an explicit schema version.
 */
import type { DeviceContext } from "../collectors/DeviceCollector";
export declare const FEATURE_SCHEMA_VERSION = "1.0.0";
export interface TypingFeatures {
    sampleCount: number;
    meanDwellTime: number;
    dwellStdDev: number;
    meanFlightTime: number;
    flightStdDev: number;
    typingSpeed: number;
    pauseRate: number;
}
export interface MouseFeatures {
    sampleCount: number;
    meanVelocity: number;
    velocityStdDev: number;
    meanAcceleration: number;
    directionChangeRate: number;
    movementDuration: number;
    totalDistance: number;
}
export interface ClickFeatures {
    clickCount: number;
    doubleClickCount: number;
    meanInterval: number;
    intervalStdDev: number;
    clickFrequency: number;
}
export interface ScrollFeatures {
    scrollEventCount: number;
    totalDistance: number;
    meanVelocity: number;
    meanPauseDuration: number;
}
export interface TouchFeatures {
    touchCount: number;
    meanDuration: number;
    meanVelocity: number;
    directionDistribution: {
        tap: number;
        up: number;
        down: number;
        left: number;
        right: number;
    };
}
export interface DeviceFeatures {
    browser: string;
    os: string;
    screenWidth: number;
    screenHeight: number;
    pixelRatio: number;
    timezoneOffset: number;
    touchSupport: boolean;
}
export interface ExtractedFeaturePayload {
    feature_schema_version: string;
    typing?: TypingFeatures;
    mouse?: MouseFeatures;
    click?: ClickFeatures;
    scroll?: ScrollFeatures;
    touch?: TouchFeatures;
    device?: DeviceContext;
}
//# sourceMappingURL=FeatureTypes.d.ts.map