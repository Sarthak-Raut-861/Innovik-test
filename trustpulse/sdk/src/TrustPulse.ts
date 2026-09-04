/**
 * @trustpulse/sdk - Main SDK Facade
 *
 * TrustPulse AI Continuous Session Security Client.
 *
 * ARCHITECTURAL BOUNDARY:
 * TrustPulse SDK is strictly a client-side telemetry and behavioral signal collection
 * component. The SDK NEVER calculates final security decisions, NEVER authorizes
 * transactions, NEVER accesses passwords or raw keystrokes, and NEVER overrides
 * server-side security policies. The backend is the sole security authority.
 */

import type { TrustPulseConfig, ValidatedTrustPulseConfig, SDKStatus } from "./config/types";
import { validateConfig } from "./config/validator";
import { SessionManager } from "./session/SessionManager";
import { PrivacyManager } from "./privacy/PrivacyManager";
import { TelemetryManager } from "./telemetry/TelemetryManager";
import { Logger } from "./utils/Logger";
import { SDKInitializationError } from "./errors/SDKError";
import { SDK_VERSION } from "./telemetry/TelemetryTypes";

export class TrustPulse {
  public static readonly version: string = SDK_VERSION;

  private readonly config: ValidatedTrustPulseConfig;
  private readonly logger: Logger;
  private readonly sessionManager: SessionManager;
  private readonly privacyManager: PrivacyManager;
  private readonly telemetryManager: TelemetryManager;
  private status: SDKStatus = "uninitialized";

  constructor(config: TrustPulseConfig) {
    try {
      this.config = validateConfig(config);
      this.logger = new Logger(this.config.debug);
      this.logger.info(`Initializing TrustPulse SDK v${TrustPulse.version}...`);

      this.sessionManager = new SessionManager(this.config.sessionId);
      this.privacyManager = new PrivacyManager(
        this.config.privacyMode,
        this.config.ignoredSelectors,
        {
          collectTyping: this.config.enableTypingSignals,
          collectMouse: this.config.enableMouseSignals,
          collectClick: this.config.enableClickSignals,
          collectScroll: this.config.enableScrollSignals,
          collectTouch: this.config.enableTouchSignals,
          collectDevice: this.config.enableDeviceSignals,
        }
      );

      this.telemetryManager = new TelemetryManager(
        this.config,
        this.sessionManager,
        this.privacyManager,
        this.logger
      );

      this.status = "ready";
      this.logger.info("TrustPulse SDK initialized and bound to session.");
    } catch (err) {
      this.status = "uninitialized";
      if (err instanceof Error) {
        throw err;
      }
      throw new SDKInitializationError("Failed to initialize TrustPulse SDK.");
    }
  }

  /**
   * Starts behavioral telemetry collection.
   */
  public start(): void {
    if (this.status === "destroyed") {
      throw new SDKInitializationError("Cannot start a destroyed TrustPulse SDK instance.");
    }
    if (this.status === "running") {
      this.logger.warn("TrustPulse SDK is already running.");
      return;
    }

    this.sessionManager.start();
    this.telemetryManager.start();
    this.status = "running";
    this.logger.info("TrustPulse SDK started.");
  }

  /**
   * Pauses signal observation and telemetry dispatch.
   */
  public pause(): void {
    if (this.status !== "running") return;
    this.sessionManager.pause();
    this.telemetryManager.pause();
    this.status = "paused";
    this.logger.info("TrustPulse SDK paused.");
  }

  /**
   * Resumes signal observation and telemetry dispatch.
   */
  public resume(): void {
    if (this.status !== "paused") return;
    this.sessionManager.resume();
    this.telemetryManager.resume();
    this.status = "running";
    this.logger.info("TrustPulse SDK resumed.");
  }

  /**
   * Stops signal observation and tears down background timers.
   */
  public stop(): void {
    if (this.status === "stopped" || this.status === "uninitialized" || this.status === "destroyed") {
      return;
    }

    this.sessionManager.stop();
    this.telemetryManager.stop();
    this.status = "stopped";
    this.logger.info("TrustPulse SDK stopped.");
  }

  /**
   * Flushes any buffered behavioral signals immediately to the backend.
   */
  public async flush(): Promise<void> {
    if (this.status === "destroyed") return;
    this.logger.debug("Flushing telemetry queue...");
    await this.telemetryManager.flush();
  }

  /**
   * Stops collection, clears all buffered telemetry, and unregisters event listeners.
   */
  public destroy(): void {
    this.stop();
    this.telemetryManager.destroy();
    this.status = "destroyed";
    this.logger.info("TrustPulse SDK destroyed.");
  }

  /**
   * Returns current operational status of the SDK.
   */
  public getStatus(): SDKStatus {
    return this.status;
  }

  /**
   * Returns the current application session ID.
   */
  public getSessionId(): string {
    return this.sessionManager.getSessionId();
  }

  /**
   * Returns the unique SDK instance identifier generated on initialization.
   */
  public getSdkInstanceId(): string {
    return this.sessionManager.getSdkInstanceId();
  }

  /**
   * Updates the host application session ID upon token rotation or re-authentication.
   */
  public updateSession(newSessionId: string): void {
    this.sessionManager.updateSessionId(newSessionId);
    this.logger.info("TrustPulse session ID updated.");
  }
}
