/**
 * @trustpulse/sdk - Telemetry Manager
 *
 * Orchestrates periodic signal sampling, local feature extraction,
 * queue management, batch dispatch, and page lifecycle unload hooks.
 */
import { TypingCollector } from "../collectors/TypingCollector";
import { MouseCollector } from "../collectors/MouseCollector";
import { ClickCollector } from "../collectors/ClickCollector";
import { ScrollCollector } from "../collectors/ScrollCollector";
import { TouchCollector } from "../collectors/TouchCollector";
import { DeviceCollector } from "../collectors/DeviceCollector";
import { TypingFeatureExtractor } from "../features/TypingFeatures";
import { MouseFeatureExtractor } from "../features/MouseFeatures";
import { ClickFeatureExtractor } from "../features/ClickFeatures";
import { ScrollFeatureExtractor } from "../features/ScrollFeatures";
import { TouchFeatureExtractor } from "../features/TouchFeatures";
import { FEATURE_SCHEMA_VERSION } from "../features/FeatureTypes";
import { TelemetryQueue } from "./TelemetryQueue";
import { TelemetryClient } from "../transport/TelemetryClient";
import { EventIdGenerator } from "../security/EventId";
import { IntegrityManager } from "../security/Integrity";
import { TimeUtils } from "../utils/Time";
import { BrowserUtils } from "../utils/Browser";
import { TELEMETRY_SCHEMA_VERSION, SDK_VERSION } from "./TelemetryTypes";
export class TelemetryManager {
    config;
    sessionManager;
    privacyManager;
    queue;
    client;
    logger;
    // Collectors
    typingCollector;
    mouseCollector;
    clickCollector;
    scrollCollector;
    touchCollector;
    deviceCollector;
    timerId = null;
    lastHarvestTime = TimeUtils.now();
    isFlushing = false;
    boundVisibilityChange;
    boundPageHide;
    constructor(config, sessionManager, privacyManager, logger) {
        this.config = config;
        this.sessionManager = sessionManager;
        this.privacyManager = privacyManager;
        this.logger = logger;
        this.queue = new TelemetryQueue(config.maxQueueSize);
        this.client = new TelemetryClient(config.apiUrl, config.publicKey, config.sessionId, config.maxRetries, logger);
        this.typingCollector = new TypingCollector(privacyManager);
        this.mouseCollector = new MouseCollector(privacyManager);
        this.clickCollector = new ClickCollector(privacyManager);
        this.scrollCollector = new ScrollCollector(privacyManager);
        this.touchCollector = new TouchCollector(privacyManager);
        this.deviceCollector = new DeviceCollector(privacyManager);
        this.boundVisibilityChange = this.handleVisibilityChange.bind(this);
        this.boundPageHide = this.handlePageHide.bind(this);
    }
    start() {
        this.logger.info("Starting telemetry collection engine...");
        // Start enabled collectors
        if (this.config.enableTypingSignals)
            this.typingCollector.start();
        if (this.config.enableMouseSignals)
            this.mouseCollector.start();
        if (this.config.enableClickSignals)
            this.clickCollector.start();
        if (this.config.enableScrollSignals)
            this.scrollCollector.start();
        if (this.config.enableTouchSignals)
            this.touchCollector.start();
        if (this.config.enableDeviceSignals)
            this.deviceCollector.start();
        // Register browser unload lifecycle listeners
        if (BrowserUtils.isBrowser()) {
            document.addEventListener("visibilitychange", this.boundVisibilityChange);
            window.addEventListener("pagehide", this.boundPageHide);
        }
        this.lastHarvestTime = TimeUtils.now();
        // Schedule background periodic harvest
        this.timerId = setInterval(() => {
            this.harvestAndDispatch().catch((err) => {
                this.logger.warn(`Periodic telemetry error: ${err instanceof Error ? err.message : String(err)}`);
            });
        }, this.config.telemetryIntervalMs);
        this.logger.info("Telemetry collection engine started.");
    }
    pause() {
        this.typingCollector.pause();
        this.mouseCollector.pause();
        this.clickCollector.pause();
        this.scrollCollector.pause();
        this.touchCollector.pause();
        this.deviceCollector.pause();
        if (this.timerId) {
            clearInterval(this.timerId);
            this.timerId = null;
        }
        this.logger.info("Telemetry collection engine paused.");
    }
    resume() {
        this.typingCollector.resume();
        this.mouseCollector.resume();
        this.clickCollector.resume();
        this.scrollCollector.resume();
        this.touchCollector.resume();
        this.deviceCollector.resume();
        this.lastHarvestTime = TimeUtils.now();
        if (!this.timerId) {
            this.timerId = setInterval(() => {
                this.harvestAndDispatch().catch((err) => {
                    this.logger.warn(`Periodic telemetry error: ${err instanceof Error ? err.message : String(err)}`);
                });
            }, this.config.telemetryIntervalMs);
        }
        this.logger.info("Telemetry collection engine resumed.");
    }
    stop() {
        if (this.timerId) {
            clearInterval(this.timerId);
            this.timerId = null;
        }
        this.typingCollector.stop();
        this.mouseCollector.stop();
        this.clickCollector.stop();
        this.scrollCollector.stop();
        this.touchCollector.stop();
        this.deviceCollector.stop();
        if (BrowserUtils.isBrowser()) {
            document.removeEventListener("visibilitychange", this.boundVisibilityChange);
            window.removeEventListener("pagehide", this.boundPageHide);
        }
        this.logger.info("Telemetry collection engine stopped.");
    }
    destroy() {
        this.stop();
        this.queue.clear();
    }
    getPrivacyManager() {
        return this.privacyManager;
    }
    getQueueSize() {
        return this.queue.size();
    }
    getDroppedCount() {
        return this.queue.getDroppedCount();
    }
    /**
     * Harvests samples from collectors, computes feature vectors, creates packet,
     * enqueues it, and dispatches batches.
     */
    async harvestAndDispatch(eventType = "behavioral_batch") {
        const packet = this.buildTelemetryPacket(eventType);
        if (packet) {
            this.queue.enqueue(packet);
        }
        await this.flushQueue();
    }
    /**
     * Forces an immediate flush of all queued telemetry.
     */
    async flush() {
        await this.harvestAndDispatch();
    }
    /**
     * Extracts features and builds a signed TelemetryPacket.
     */
    buildTelemetryPacket(eventType = "behavioral_batch") {
        const now = TimeUtils.now();
        const windowDuration = TimeUtils.delta(this.lastHarvestTime, now);
        this.lastHarvestTime = now;
        // Collect raw samples
        const typingSamples = this.typingCollector.getAndResetSamples();
        const mouseSamples = this.mouseCollector.getAndResetSamples();
        const clickSamples = this.clickCollector.getAndResetSamples();
        const scrollSamples = this.scrollCollector.getAndResetSamples();
        const touchSamples = this.touchCollector.getAndResetSamples();
        const deviceContext = this.deviceCollector.getContext();
        // Check if there is any signal data to report
        const hasActivity = typingSamples.length > 0 ||
            mouseSamples.length > 0 ||
            clickSamples.length > 0 ||
            scrollSamples.length > 0 ||
            touchSamples.length > 0;
        // Send packet if activity occurred or if it's a lifecycle event
        if (!hasActivity && eventType === "behavioral_batch") {
            return null;
        }
        // Extract features locally
        const features = {
            feature_schema_version: FEATURE_SCHEMA_VERSION,
        };
        if (this.config.enableTypingSignals && typingSamples.length > 0) {
            features.typing = TypingFeatureExtractor.extract(typingSamples, windowDuration);
        }
        if (this.config.enableMouseSignals && mouseSamples.length > 0) {
            features.mouse = MouseFeatureExtractor.extract(mouseSamples);
        }
        if (this.config.enableClickSignals && clickSamples.length > 0) {
            features.click = ClickFeatureExtractor.extract(clickSamples, windowDuration);
        }
        if (this.config.enableScrollSignals && scrollSamples.length > 0) {
            features.scroll = ScrollFeatureExtractor.extract(scrollSamples);
        }
        if (this.config.enableTouchSignals && touchSamples.length > 0) {
            features.touch = TouchFeatureExtractor.extract(touchSamples);
        }
        if (this.config.enableDeviceSignals && deviceContext) {
            features.device = deviceContext;
        }
        const eventId = EventIdGenerator.generate();
        const sequenceNumber = this.sessionManager.nextSequence();
        const timestamp = TimeUtils.epoch();
        // Assemble packet
        const packet = {
            sessionId: this.sessionManager.getSessionId(),
            sdkInstanceId: this.sessionManager.getSdkInstanceId(),
            eventId,
            sequenceNumber,
            timestamp,
            schemaVersion: TELEMETRY_SCHEMA_VERSION,
            sdkVersion: SDK_VERSION,
            eventType,
            features,
            metadata: {
                pageContext: BrowserUtils.isBrowser() ? window.location.pathname : undefined,
                pageVisibility: BrowserUtils.isVisibilitySupported() ? document.visibilityState : undefined,
            },
        };
        // Calculate integrity checksum
        const serialized = JSON.stringify(packet.features);
        packet.integrity = IntegrityManager.computeChecksum(serialized);
        return packet;
    }
    async flushQueue() {
        if (this.isFlushing || this.queue.isEmpty())
            return;
        this.isFlushing = true;
        try {
            while (!this.queue.isEmpty()) {
                const batchPackets = this.queue.dequeueBatch(this.config.batchSize);
                if (batchPackets.length === 0)
                    break;
                const batch = {
                    batchId: EventIdGenerator.generate(),
                    sentAt: TimeUtils.epoch(),
                    packets: batchPackets,
                };
                const response = await this.client.sendBatch(batch);
                if (!response.success && response.retryable) {
                    // Put back on queue
                    this.queue.requeue(batchPackets);
                    break;
                }
            }
        }
        finally {
            this.isFlushing = false;
        }
    }
    handleVisibilityChange() {
        if (document.visibilityState === "hidden") {
            this.flushViaBeaconOrFetch();
        }
    }
    handlePageHide() {
        this.flushViaBeaconOrFetch();
    }
    flushViaBeaconOrFetch() {
        const packet = this.buildTelemetryPacket("session_stop");
        if (packet) {
            this.queue.enqueue(packet);
        }
        if (this.queue.isEmpty())
            return;
        const batchPackets = this.queue.dequeueBatch(this.config.batchSize * 2);
        const batch = {
            batchId: EventIdGenerator.generate(),
            sentAt: TimeUtils.epoch(),
            packets: batchPackets,
        };
        const sent = this.client.sendBeacon(batch);
        if (!sent) {
            // If sendBeacon fails, attempt keepalive fetch fire-and-forget
            this.client.sendBatch(batch).catch(() => { });
        }
    }
}
//# sourceMappingURL=TelemetryManager.js.map