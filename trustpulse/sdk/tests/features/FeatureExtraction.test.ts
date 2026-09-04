import { describe, it, expect } from "vitest";
import { TypingFeatureExtractor } from "../../src/features/TypingFeatures";
import { MouseFeatureExtractor } from "../../src/features/MouseFeatures";
import { ClickFeatureExtractor } from "../../src/features/ClickFeatures";
import { ScrollFeatureExtractor } from "../../src/features/ScrollFeatures";
import { TouchFeatureExtractor } from "../../src/features/TouchFeatures";

describe("Feature Extraction & Numerical Bounds", () => {
  describe("TypingFeatureExtractor", () => {
    it("handles empty keystroke array safely without NaN", () => {
      const features = TypingFeatureExtractor.extract([]);
      expect(features.sampleCount).toBe(0);
      expect(features.meanDwellTime).toBe(0);
      expect(features.dwellStdDev).toBe(0);
      expect(features.meanFlightTime).toBe(0);
      expect(features.typingSpeed).toBe(0);
      expect(Number.isNaN(features.meanDwellTime)).toBe(false);
    });

    it("extracts accurate dwell and flight statistics", () => {
      const samples = [
        { dwellTime: 100, flightTime: 150 },
        { dwellTime: 120, flightTime: 200 },
        { dwellTime: 80, flightTime: 1200 }, // pause > 1000ms
      ];

      const features = TypingFeatureExtractor.extract(samples, 3000);
      expect(features.sampleCount).toBe(3);
      expect(features.meanDwellTime).toBe(100);
      expect(features.dwellStdDev).toBeGreaterThan(0);
      expect(features.meanFlightTime).toBeGreaterThan(0);
      expect(features.pauseRate).toBeCloseTo(1 / 3, 2);
    });
  });

  describe("MouseFeatureExtractor", () => {
    it("handles empty and single sample streams without error", () => {
      const empty = MouseFeatureExtractor.extract([]);
      expect(empty.sampleCount).toBe(0);
      expect(empty.meanVelocity).toBe(0);
      expect(Number.isNaN(empty.meanVelocity)).toBe(false);

      const single = MouseFeatureExtractor.extract([{ x: 10, y: 20, timestamp: 1000 }]);
      expect(single.sampleCount).toBe(1);
      expect(single.meanVelocity).toBe(0);
    });

    it("calculates velocity, acceleration, and distance safely", () => {
      const samples = [
        { x: 0, y: 0, timestamp: 0 },
        { x: 30, y: 40, timestamp: 100 }, // distance = 50, dt = 0.1s, v = 500 px/s
        { x: 90, y: 120, timestamp: 200 }, // distance = 78.1, dt = 0.1s
      ];

      const features = MouseFeatureExtractor.extract(samples);
      expect(features.sampleCount).toBe(3);
      expect(features.meanVelocity).toBeGreaterThan(0);
      expect(features.totalDistance).toBeGreaterThan(100);
      expect(Number.isFinite(features.meanVelocity)).toBe(true);
      expect(Number.isFinite(features.meanAcceleration)).toBe(true);
    });
  });

  describe("ClickFeatureExtractor", () => {
    it("extracts click intervals and frequency", () => {
      const samples = [
        { timestamp: 100, intervalFromLastClick: 0, isDoubleClick: false, elementCategory: "button" },
        { timestamp: 250, intervalFromLastClick: 150, isDoubleClick: true, elementCategory: "button" },
      ];

      const features = ClickFeatureExtractor.extract(samples, 3000);
      expect(features.clickCount).toBe(2);
      expect(features.doubleClickCount).toBe(1);
      expect(features.meanInterval).toBe(150);
      expect(Number.isFinite(features.clickFrequency)).toBe(true);
    });
  });

  describe("ScrollFeatureExtractor", () => {
    it("extracts scroll statistics", () => {
      const samples = [
        { timestamp: 100, deltaY: 200, duration: 50 },
        { timestamp: 800, deltaY: 100, duration: 700 }, // pause > 500ms
      ];

      const features = ScrollFeatureExtractor.extract(samples);
      expect(features.scrollEventCount).toBe(2);
      expect(features.totalDistance).toBe(300);
      expect(features.meanVelocity).toBeGreaterThan(0);
      expect(features.meanPauseDuration).toBe(700);
    });
  });

  describe("TouchFeatureExtractor", () => {
    it("extracts gesture velocity and direction distribution", () => {
      const samples = [
        { duration: 100, distance: 150, velocity: 1500, direction: "left" as const },
        { duration: 50, distance: 5, velocity: 100, direction: "tap" as const },
      ];

      const features = TouchFeatureExtractor.extract(samples);
      expect(features.touchCount).toBe(2);
      expect(features.meanVelocity).toBe(800);
      expect(features.directionDistribution.left).toBe(1);
      expect(features.directionDistribution.tap).toBe(1);
    });
  });
});
