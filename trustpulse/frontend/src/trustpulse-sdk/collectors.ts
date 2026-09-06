/**
 * TRUSTPULSE SDK — behavioral collectors.
 *
 * Every collector consumes raw DOM events in memory and emits ONLY derived
 * aggregate statistics. Nothing here ever records which key was pressed, what
 * was typed, or what text an element contained.
 */

import { pushBounded } from './privacy';

export interface TypingStats {
  sampleCount: number;
  meanDwellTime: number;
  dwellStdDev: number;
  meanFlightTime: number;
  flightStdDev: number;
  typingSpeed: number;
  pauseRate: number;
}

export interface MouseStats {
  sampleCount: number;
  meanVelocity: number;
  velocityStdDev: number;
  meanAcceleration: number;
  directionChangeRate: number;
  totalDistance: number;
  movementDuration: number;
  meanPauseTime: number;
}

export interface ClickStats {
  clickCount: number;
  doubleClickCount: number;
  meanInterval: number;
  intervalStdDev: number;
  clickFrequency: number;
}

export interface ScrollStats {
  scrollEventCount: number;
  totalDistance: number;
  meanVelocity: number;
  meanPauseDuration: number;
  eventRate: number;
}

export interface DerivedFeatures {
  typing?: TypingStats;
  mouse?: MouseStats;
  click?: ClickStats;
  scroll?: ScrollStats;
}

const MAX_SAMPLES = 600;
const PAUSE_MS = 800;

export function mean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

export function stdDev(values: number[]): number {
  if (values.length < 2) return 0;
  const avg = mean(values);
  const variance = mean(values.map((v) => (v - avg) ** 2));
  return Math.sqrt(variance);
}

function round(value: number, digits = 3): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

/** Typing rhythm: dwell/flight timings only. `event.key` is never read. */
export class TypingCollector {
  private dwells: number[] = [];
  private flights: number[] = [];
  private lastDown = 0;
  private lastUp = 0;
  private pauses = 0;
  private firstEventAt = 0;
  private keyCount = 0;

  onKeyDown(timestamp: number): void {
    if (this.firstEventAt === 0) this.firstEventAt = timestamp;
    if (this.lastUp > 0) {
      const flight = timestamp - this.lastUp;
      if (flight > PAUSE_MS) this.pauses += 1;
      else pushBounded(this.flights, flight, MAX_SAMPLES);
    }
    this.lastDown = timestamp;
    this.keyCount += 1;
  }

  onKeyUp(timestamp: number): void {
    if (this.lastDown > 0) pushBounded(this.dwells, timestamp - this.lastDown, MAX_SAMPLES);
    this.lastUp = timestamp;
  }

  stats(): TypingStats | undefined {
    if (this.keyCount < 4) return undefined;
    const windowMs = Math.max(1, (this.lastUp || performance.now()) - this.firstEventAt);
    return {
      sampleCount: this.keyCount,
      meanDwellTime: round(mean(this.dwells), 2),
      dwellStdDev: round(stdDev(this.dwells), 2),
      meanFlightTime: round(mean(this.flights), 2),
      flightStdDev: round(stdDev(this.flights), 2),
      typingSpeed: round((this.keyCount / windowMs) * 1000, 3),
      pauseRate: round(this.pauses / Math.max(1, this.keyCount), 4),
    };
  }

  reset(): void {
    this.dwells = [];
    this.flights = [];
    this.pauses = 0;
    this.keyCount = 0;
    this.firstEventAt = 0;
    this.lastDown = 0;
    this.lastUp = 0;
  }
}

/** Pointer kinematics: velocity, acceleration, direction changes, pauses. */
export class MouseCollector {
  private velocities: number[] = [];
  private accelerations: number[] = [];
  private directions: number[] = [];
  private pauses: number[] = [];
  private totalDistance = 0;
  private movementDuration = 0;
  private sampleCount = 0;
  private last: { x: number; y: number; t: number } | null = null;
  private lastMoveAt = 0;

  onMove(x: number, y: number, timestamp: number): void {
    if (this.last) {
      const dt = Math.max(1, timestamp - this.last.t);
      const distance = Math.hypot(x - this.last.x, y - this.last.y);
      const velocity = (distance / dt) * 1000;
      const direction = Math.atan2(y - this.last.y, x - this.last.x);

      pushBounded(this.velocities, velocity, MAX_SAMPLES);
      if (this.velocities.length >= 2) {
        const previous = this.velocities[this.velocities.length - 2];
        pushBounded(this.accelerations, Math.abs(velocity - previous) / (dt / 1000), MAX_SAMPLES);
      }
      if (this.directions.length > 0) {
        const previousDirection = this.directions[this.directions.length - 1];
        const delta = Math.abs(direction - previousDirection);
        if (delta > 0.35) pushBounded(this.directions, direction, MAX_SAMPLES);
      } else {
        pushBounded(this.directions, direction, MAX_SAMPLES);
      }

      this.totalDistance += distance;
      this.movementDuration += dt;
      this.sampleCount += 1;

      if (this.lastMoveAt > 0) {
        const idle = timestamp - this.lastMoveAt;
        if (idle > PAUSE_MS) pushBounded(this.pauses, idle, MAX_SAMPLES);
      }
    }
    this.last = { x, y, t: timestamp };
    this.lastMoveAt = timestamp;
  }

  stats(): MouseStats | undefined {
    if (this.sampleCount < 5) return undefined;
    const seconds = this.movementDuration / 1000;
    return {
      sampleCount: this.sampleCount,
      meanVelocity: round(mean(this.velocities), 2),
      velocityStdDev: round(stdDev(this.velocities), 2),
      meanAcceleration: round(mean(this.accelerations), 2),
      directionChangeRate: round(this.directions.length / Math.max(0.001, seconds), 3),
      totalDistance: round(this.totalDistance, 1),
      movementDuration: round(this.movementDuration, 1),
      meanPauseTime: round(mean(this.pauses), 1),
    };
  }

  reset(): void {
    this.velocities = [];
    this.accelerations = [];
    this.directions = [];
    this.pauses = [];
    this.totalDistance = 0;
    this.movementDuration = 0;
    this.sampleCount = 0;
    this.last = null;
    this.lastMoveAt = 0;
  }
}

/** Click cadence: intervals and frequency only. Never the click target's text. */
export class ClickCollector {
  private intervals: number[] = [];
  private clickCount = 0;
  private doubleClickCount = 0;
  private lastClickAt = 0;
  private firstClickAt = 0;

  onClick(timestamp: number, detail = 1): void {
    if (this.firstClickAt === 0) this.firstClickAt = timestamp;
    if (this.lastClickAt > 0) pushBounded(this.intervals, timestamp - this.lastClickAt, MAX_SAMPLES);
    if (detail > 1) this.doubleClickCount += 1;
    this.clickCount += 1;
    this.lastClickAt = timestamp;
  }

  stats(): ClickStats | undefined {
    if (this.clickCount < 3) return undefined;
    const seconds = Math.max(0.001, ((this.lastClickAt || performance.now()) - this.firstClickAt) / 1000);
    return {
      clickCount: this.clickCount,
      doubleClickCount: this.doubleClickCount,
      meanInterval: round(mean(this.intervals), 2),
      intervalStdDev: round(stdDev(this.intervals), 2),
      clickFrequency: round(this.clickCount / seconds, 3),
    };
  }

  reset(): void {
    this.intervals = [];
    this.clickCount = 0;
    this.doubleClickCount = 0;
    this.lastClickAt = 0;
    this.firstClickAt = 0;
  }
}

/** Scroll behaviour: distance, velocity and pause durations. */
export class ScrollCollector {
  private velocities: number[] = [];
  private pauses: number[] = [];
  private totalDistance = 0;
  private eventCount = 0;
  private firstAt = 0;
  private lastAt = 0;

  onScroll(deltaY: number, timestamp: number): void {
    if (this.firstAt === 0) this.firstAt = timestamp;
    if (this.lastAt > 0) {
      const dt = Math.max(1, timestamp - this.lastAt);
      pushBounded(this.velocities, (Math.abs(deltaY) / dt) * 1000, MAX_SAMPLES);
      if (dt > PAUSE_MS) pushBounded(this.pauses, dt, MAX_SAMPLES);
    }
    this.totalDistance += Math.abs(deltaY);
    this.eventCount += 1;
    this.lastAt = timestamp;
  }

  stats(): ScrollStats | undefined {
    if (this.eventCount < 3) return undefined;
    const seconds = Math.max(0.001, ((this.lastAt || performance.now()) - this.firstAt) / 1000);
    return {
      scrollEventCount: this.eventCount,
      totalDistance: round(this.totalDistance, 1),
      meanVelocity: round(mean(this.velocities), 2),
      meanPauseDuration: round(mean(this.pauses), 1),
      eventRate: round(this.eventCount / seconds, 3),
    };
  }

  reset(): void {
    this.velocities = [];
    this.pauses = [];
    this.totalDistance = 0;
    this.eventCount = 0;
    this.firstAt = 0;
    this.lastAt = 0;
  }
}
