/**
 * TRUSTPULSE SDK — client.
 *
 * Binds collectors to a session, batches derived features and posts them to the
 * TRUSTPULSE platform API. It performs NO trust evaluation: scoring, state and
 * authorization all happen server-side.
 */

import {
  ClickCollector,
  MouseCollector,
  ScrollCollector,
  TypingCollector,
  type DerivedFeatures,
} from './collectors';
import { deviceFingerprint, sanitizeFeatures } from './privacy';

export interface TrustPulseClientOptions {
  /** Absolute or relative API base. Defaults to the relative platform prefix. */
  apiBase?: string;
  /** Server-side integration key (see services/api.ts for the demo caveat). */
  apiKey: string;
  tenantId?: string;
  /** Milliseconds between telemetry flushes. */
  flushIntervalMs?: number;
  /** Called with every flush result so the UI can react to trust changes. */
  onTrustUpdate?: (result: unknown) => void;
  onError?: (error: unknown) => void;
  /** Attach listeners to this element instead of the document. */
  target?: HTMLElement | Document;
}

export interface SessionBinding {
  sessionId: string;
  device: ReturnType<typeof deviceFingerprint>;
}

const DEFAULT_FLUSH_MS = 5000;

export class TrustPulseClient {
  private readonly options: Required<
    Pick<TrustPulseClientOptions, 'apiBase' | 'apiKey' | 'flushIntervalMs'>
  > &
    TrustPulseClientOptions;
  private readonly typing = new TypingCollector();
  private readonly mouse = new MouseCollector();
  private readonly click = new ClickCollector();
  private readonly scroll = new ScrollCollector();
  private timer: number | null = null;
  private binding: SessionBinding | null = null;
  private running = false;
  private inFlight = false;
  private attached: Array<[EventTarget, string, EventListener]> = [];

  constructor(options: TrustPulseClientOptions) {
    this.options = {
      apiBase: '/api/v1',
      flushIntervalMs: DEFAULT_FLUSH_MS,
      ...options,
    };
  }

  get sessionId(): string | null {
    return this.binding?.sessionId ?? null;
  }

  get isRunning(): boolean {
    return this.running;
  }

  /** Binds the collectors to a session and starts collection. */
  start(sessionId: string): void {
    if (this.running) this.stop();
    this.binding = { sessionId, device: deviceFingerprint() };
    this.attach();
    this.running = true;
    this.timer = window.setInterval(() => void this.flush(), this.options.flushIntervalMs ?? DEFAULT_FLUSH_MS);
  }

  stop(): void {
    if (this.timer !== null) {
      window.clearInterval(this.timer);
      this.timer = null;
    }
    this.detach();
    this.running = false;
    this.binding = null;
    this.resetCollectors();
  }

  /** Emits derived features immediately (used by the demo controls). */
  async flush(): Promise<void> {
    if (!this.binding || this.inFlight) return;
    const features = this.snapshot();
    if (Object.keys(features).length === 0) return;

    this.inFlight = true;
    try {
      const response = await fetch(`${this.options.apiBase}/telemetry`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-TrustPulse-API-Key': this.options.apiKey,
          'X-TrustPulse-Tenant-Id': this.options.tenantId ?? 'trustdev-demo',
          'X-TrustPulse-SDK-Version': '1.0.0',
        },
        body: JSON.stringify({
          session_id: this.binding.sessionId,
          features: sanitizeFeatures(features),
          source: 'SDK',
          sample_metadata: { sdk: 'trustpulse-web', version: '1.0.0' },
        }),
      });
      if (!response.ok) {
        throw new Error(`telemetry rejected (${response.status})`);
      }
      const body = (await response.json()) as { trust?: unknown };
      this.resetCollectors();
      if (body.trust) this.options.onTrustUpdate?.(body.trust);
    } catch (error) {
      this.options.onError?.(error);
    } finally {
      this.inFlight = false;
    }
  }

  /** Current derived features without sending them. */
  snapshot(): DerivedFeatures {
    const features: DerivedFeatures = {};
    const typing = this.typing.stats();
    const mouse = this.mouse.stats();
    const click = this.click.stats();
    const scroll = this.scroll.stats();
    if (typing) features.typing = typing;
    if (mouse) features.mouse = mouse;
    if (click) features.click = click;
    if (scroll) features.scroll = scroll;
    return features;
  }

  // ------------------------------------------------------------------ internals
  private attach(): void {
    const target: EventTarget = this.options.target ?? (typeof document !== 'undefined' ? document : window);

    const onKeyDown = (event: Event) => this.typing.onKeyDown((event as KeyboardEvent).timeStamp || performance.now());
    const onKeyUp = (event: Event) => this.typing.onKeyUp((event as KeyboardEvent).timeStamp || performance.now());
    const onMouseMove = (event: Event) => {
      const mouseEvent = event as MouseEvent;
      this.mouse.onMove(mouseEvent.clientX, mouseEvent.clientY, mouseEvent.timeStamp || performance.now());
    };
    const onClick = (event: Event) => {
      const mouseEvent = event as MouseEvent;
      this.click.onClick(mouseEvent.timeStamp || performance.now(), mouseEvent.detail);
    };
    const onScroll = (event: Event) => {
      const wheelEvent = event as WheelEvent;
      this.scroll.onScroll(wheelEvent.deltaY ?? 0, wheelEvent.timeStamp || performance.now());
    };

    // Passive listeners: the SDK must never slow the protected application down.
    const pairs: Array<[string, EventListener]> = [
      ['keydown', onKeyDown],
      ['keyup', onKeyUp],
      ['mousemove', onMouseMove],
      ['click', onClick],
      ['wheel', onScroll],
    ];
    for (const [type, listener] of pairs) {
      target.addEventListener(type, listener, { passive: true });
      this.attached.push([target, type, listener]);
    }
  }

  private detach(): void {
    for (const [target, type, listener] of this.attached) {
      target.removeEventListener(type, listener);
    }
    this.attached = [];
  }

  private resetCollectors(): void {
    this.typing.reset();
    this.mouse.reset();
    this.click.reset();
    this.scroll.reset();
  }
}

export { deviceFingerprint };
