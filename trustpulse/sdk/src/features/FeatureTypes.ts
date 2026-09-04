/**
 * @trustpulse/sdk - Feature Schemas & Types
 *
 * All extracted features are strictly numerical, normalized where appropriate,
 * bounded to prevent NaN/Infinity, and tagged with an explicit schema version.
 */

import type { DeviceContext } from "../collectors/DeviceCollector";

export const FEATURE_SCHEMA_VERSION = "1.0.0";

export interface TypingFeatures {
  sampleCount: number;
  meanDwellTime: number;      // ms
  dwellStdDev: number;        // ms
  meanFlightTime: number;     // ms
  flightStdDev: number;       // ms
  typingSpeed: number;        // keystrokes per second
  pauseRate: number;          // pauses (>1000ms) per keystroke
}

export interface MouseFeatures {
  sampleCount: number;
  meanVelocity: number;       // px/sec
  velocityStdDev: number;     // px/sec
  meanAcceleration: number;   // px/sec^2
  directionChangeRate: number;// rad/sec
  movementDuration: number;   // total ms in motion
  totalDistance: number;      // px
}

export interface ClickFeatures {
  clickCount: number;
  doubleClickCount: number;
  meanInterval: number;       // ms
  intervalStdDev: number;     // ms
  clickFrequency: number;     // clicks per minute
}

export interface ScrollFeatures {
  scrollEventCount: number;
  totalDistance: number;      // px
  meanVelocity: number;       // px/sec
  meanPauseDuration: number;  // ms
}

export interface TouchFeatures {
  touchCount: number;
  meanDuration: number;       // ms
  meanVelocity: number;       // px/sec
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
