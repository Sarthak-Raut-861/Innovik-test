/**
 * @trustpulse/sdk - Base Collector Abstraction
 *
 * Provides a standardized lifecycle and safe event listener management
 * across all behavioral collectors.
 */

export abstract class BaseCollector {
  protected active = false;
  protected paused = false;

  public abstract start(): void;
  public abstract stop(): void;
  public abstract clear(): void;

  public pause(): void {
    this.paused = true;
  }

  public resume(): void {
    this.paused = false;
  }

  public isActive(): boolean {
    return this.active && !this.paused;
  }
}
