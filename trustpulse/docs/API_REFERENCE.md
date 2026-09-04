# TrustPulse AI — SDK API Reference

## `TrustPulse`

The primary client facade exported by `@trustpulse/sdk`.

### Constructor

```typescript
new TrustPulse(config: TrustPulseConfig)
```

#### Parameters

* `config.apiUrl`: `string` (Required) — Base URL of the TrustPulse ingestion endpoint. Must be HTTPS in production.
* `config.publicKey`: `string` (Required) — Non-secret customer public application key.
* `config.sessionId`: `string` (Required) — Authenticated host application session ID.
* `config.telemetryIntervalMs`: `number` (Optional, Default: `3000`) — Periodic telemetry dispatch interval (1000ms – 60000ms).
* `config.maxQueueSize`: `number` (Optional, Default: `500`) — Maximum items buffered before FIFO drop.
* `config.batchSize`: `number` (Optional, Default: `10`) — Batch size for outgoing HTTPS transmissions.
* `config.maxRetries`: `number` (Optional, Default: `3`) — Maximum retries on 5xx/transient errors.
* `config.enableTypingSignals`: `boolean` (Optional, Default: `true`)
* `config.enableMouseSignals`: `boolean` (Optional, Default: `true`)
* `config.enableClickSignals`: `boolean` (Optional, Default: `true`)
* `config.enableScrollSignals`: `boolean` (Optional, Default: `true`)
* `config.enableTouchSignals`: `boolean` (Optional, Default: `true`)
* `config.enableDeviceSignals`: `boolean` (Optional, Default: `true`)
* `config.privacyMode`: `"standard" | "strict"` (Optional, Default: `"standard"`)
* `config.debug`: `boolean` (Optional, Default: `false`)
* `config.ignoredSelectors`: `string[]` (Optional, Default: `[]`)

### Methods

* `start(): void` — Starts signal observation and scheduled telemetry dispatches.
* `stop(): void` — Halts collection and clears intervals.
* `pause(): void` — Temporarily pauses collection.
* `resume(): void` — Resumes collection.
* `flush(): Promise<void>` — Forces an immediate feature extraction and batch transmission.
* `destroy(): void` — Halts collection, unregisters all event listeners, flushes pending unload beacon, and clears memory buffers.
* `getStatus(): SDKStatus` — Returns current state (`"uninitialized" | "ready" | "running" | "paused" | "stopped" | "destroyed"`).
* `getSessionId(): string` — Returns active session ID.
* `getSdkInstanceId(): string` — Returns unique random SDK instance UUID.
* `updateSession(newSessionId: string): void` — Updates session ID upon session renewal.
* `static readonly version: string` — Current SDK version (e.g. `"1.0.0"`).
