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

---

# TrustPulse Phase 2 — Security Backend API

Phase 2 adds the production-grade tenant-scoped backend. All routes are prefixed
with `/v1`. OpenAPI documentation is available at `/docs`.

## Authentication

- **Server-side customer calls** (`/sessions`, `/risk/evaluate`, `/incidents`,
  `/actions`): `Authorization: Bearer <api_key>` or `X-TrustPulse-API-Key: <api_key>`.
- **Browser SDK telemetry** (`/telemetry`): `X-TrustPulse-Public-Key: <public_key>`
  plus `X-TrustPulse-Session-Id` binding. Public key is non-secret identification only.
- **Development fallback** (disable in production): `X-TrustPulse-Tenant-Id` header.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/sessions` | Register/bind a session |
| GET | `/v1/sessions/{session_id}` | Read tenant-scoped session |
| PATCH | `/v1/sessions/{session_id}/status` | Update lifecycle status |
| POST | `/v1/telemetry` | SDK batch telemetry ingestion |
| POST | `/v1/telemetry/batch` | Backward-compatible alias |
| POST | `/v1/risk/evaluate` | Fresh risk evaluation + policy decision |
| GET | `/v1/incidents` | List tenant incidents |
| GET | `/v1/incidents/{incident_id}` | Get incident |
| POST | `/v1/incidents/{incident_id}/resolve` | Resolve incident |
| GET | `/v1/actions` | List action requests |
| GET | `/v1/actions/{action_id}` | Get action request |
| GET | `/v1/actions/catalog` | Generic action-risk catalog |
| GET | `/v1/health` | Liveness/dependency state |
| GET | `/v1/health/ready` | Readiness |
| GET | `/v1/health/metrics` | Non-sensitive operational counters |

## Decisions

`ALLOW`, `STEP_UP`, `BLOCK`, `ISOLATE`.

## Error codes

`401` missing/invalid credential, `403` cross-tenant, `404` not found,
`409` replay/terminal state, `413` oversized payload, `422` validation,
`429` rate limit, `503` security infrastructure unavailable.
