import { createHash } from "node:crypto";
import {
  MissingHeaderError,
  WebhookConfigurationError,
  WebhookHandlerTimeoutError,
  WebhookPayloadError,
  WebhookSignatureError,
  WebhookTimestampError,
} from "./errors.js";
import type {
  HookGuardOptions,
  IncomingHeaders,
  ProviderConfig,
  ProviderName,
  RawBody,
  WebhookEvent,
  WebhookHandler,
  WebhookResponse,
} from "./types.js";
import { assertValidProviderConfig, constructEvent } from "./verify.js";

export interface HttpRequestLike {
  body: unknown;
  headers: IncomingHeaders;
  originalUrl?: string;
  url?: string;
  method?: string;
  /** Set by the middleware when `callNext` is true. */
  webhookEvent?: WebhookEvent;
}

export interface HttpResponseLike {
  status(code: number): {
    json(body: unknown): unknown;
    send?(body: unknown): unknown;
  };
  setHeader?(name: string, value: string): unknown;
}

export type NextFunctionLike = (err?: unknown) => void;

export interface MiddlewareOptions {
  /**
   * `after-handlers` responds once handlers finish, and returns 500 if one
   * fails so the provider retries. `immediate` responds 200 before handlers
   * run: use it only when handlers cannot finish within the provider's
   * deadline, because a failed event is then not retried.
   * @default "after-handlers"
   */
  ack?: "after-handlers" | "immediate";
  /**
   * Instead of responding, set `req.webhookEvent` and call `next()`, leaving
   * the response to your own route. Failures go to `next(err)`.
   */
  callNext?: boolean;
}

interface Registration {
  provider: ProviderName;
  pattern: string;
  handler: WebhookHandler;
}

interface Outcome {
  error?: unknown;
  response?: WebhookResponse;
}

const PROCESSING_FAILED: WebhookResponse = {
  status: 500,
  body: { error: "Webhook processing failed" },
};

const TWILIO_EMPTY_RESPONSE: WebhookResponse = {
  contentType: "text/xml",
  body: "<Response/>",
};

export class HookGuard {
  private readonly registrations: Registration[] = [];
  private readonly options: HookGuardOptions;

  constructor(options: HookGuardOptions) {
    if (!options?.providers || typeof options.providers !== "object") {
      throw new WebhookConfigurationError(
        "HookGuard requires a providers object"
      );
    }
    for (const [provider, config] of Object.entries(options.providers)) {
      assertValidProviderConfig(provider, config);
    }
    const { handlerTimeoutMs } = options;
    if (
      handlerTimeoutMs !== undefined &&
      !(Number.isFinite(handlerTimeoutMs) && handlerTimeoutMs > 0)
    ) {
      throw new WebhookConfigurationError(
        "handlerTimeoutMs must be a positive number"
      );
    }
    this.options = options;
  }

  /**
   * Register a handler. Patterns are an exact type, a `prefix.*` wildcard, or
   * `*` for every event. The provider may be omitted only when exactly one is
   * configured, so one provider's events cannot reach another's handler.
   */
  on<TPayload = Record<string, unknown>>(
    eventType: string,
    handler: WebhookHandler<TPayload>
  ): this;
  on<TPayload = Record<string, unknown>>(
    provider: ProviderName,
    eventType: string,
    handler: WebhookHandler<TPayload>
  ): this;
  on(
    providerOrType: string,
    typeOrHandler: string | WebhookHandler,
    maybeHandler?: WebhookHandler
  ): this {
    if (typeof typeOrHandler === "function") {
      this.registrations.push({
        provider: this.onlyProvider(),
        pattern: providerOrType,
        handler: typeOrHandler,
      });
      return this;
    }

    const provider = providerOrType as ProviderName;
    this.requireConfig(provider);
    if (typeof maybeHandler !== "function") {
      throw new WebhookConfigurationError("on() requires a handler function");
    }
    this.registrations.push({
      provider,
      pattern: typeOrHandler,
      handler: maybeHandler,
    });
    return this;
  }

  constructEvent(provider: ProviderName, req: HttpRequestLike): WebhookEvent {
    const config = this.requireConfig(provider);

    return constructEvent(provider, req.body as RawBody, req.headers, config.secret, {
      url: resolveUrl(config, req),
      method: req.method,
      algorithm: config.algorithm,
      tolerance: config.tolerance,
      allowLegacySha1: config.allowLegacySha1,
    });
  }

  middleware(provider: ProviderName, options: MiddlewareOptions = {}) {
    this.requireConfig(provider);
    const ack = options.ack ?? "after-handlers";
    if (ack === "immediate" && options.callNext) {
      throw new WebhookConfigurationError(
        'ack: "immediate" sends the response, so it cannot be combined with callNext'
      );
    }

    return async (
      req: HttpRequestLike,
      res: HttpResponseLike,
      next: NextFunctionLike
    ): Promise<void> => {
      try {
        let event: WebhookEvent;
        try {
          event = this.constructEvent(provider, req);
        } catch (error) {
          this.report(error);
          sendResponse(res, failureResponse(error));
          return;
        }

        const handshake = handshakeResponse(event);
        if (handshake) {
          sendResponse(res, handshake);
          return;
        }

        if (ack === "immediate") {
          sendResponse(res, defaultResponse(provider));
          await this.process(event);
          return;
        }

        const outcome = await this.process(event);
        if (options.callNext) {
          req.webhookEvent = event;
          next(outcome.error);
          return;
        }
        sendResponse(
          res,
          outcome.error === undefined
            ? (outcome.response ?? defaultResponse(provider))
            : PROCESSING_FAILED
        );
      } catch (error) {
        this.report(error);
        next(error);
      }
    };
  }

  private onlyProvider(): ProviderName {
    const configured = Object.keys(this.options.providers) as ProviderName[];
    const [provider] = configured;
    if (configured.length !== 1 || provider === undefined) {
      throw new WebhookConfigurationError(
        'With several providers configured, name one: on("stripe", "charge.failed", handler)'
      );
    }
    return provider;
  }

  private requireConfig(provider: ProviderName): ProviderConfig {
    const config = Object.hasOwn(this.options.providers, provider)
      ? this.options.providers[provider]
      : undefined;
    if (!config) {
      throw new WebhookConfigurationError(`Provider "${provider}" is not configured`);
    }
    return config;
  }

  private async process(event: WebhookEvent): Promise<Outcome> {
    const store = this.options.idempotency;
    if (!store) {
      return this.dispatch(event);
    }

    const key = idempotencyKey(event);
    try {
      if (!(await store.claim(key, event))) {
        return {};
      }
    } catch (error) {
      this.report(error, event);
      return { error };
    }

    const outcome = await this.dispatch(event);
    if (outcome.error !== undefined) {
      try {
        await store.release?.(key, event);
      } catch (error) {
        this.report(error, event);
      }
    }
    return outcome;
  }

  private async dispatch(event: WebhookEvent): Promise<Outcome> {
    const outcome: Outcome = {};
    for (const item of event.batch ?? [event]) {
      for (const { provider, pattern, handler } of this.registrations) {
        if (provider !== item.provider || !matches(pattern, item.type)) {
          continue;
        }
        try {
          const response = await this.invoke(handler, item);
          outcome.response ??= response ?? undefined;
        } catch (error) {
          outcome.error ??= error;
          this.report(error, item);
        }
      }
    }
    return outcome;
  }

  private async invoke(
    handler: WebhookHandler,
    event: WebhookEvent
  ): Promise<void | WebhookResponse> {
    const timeoutMs = this.options.handlerTimeoutMs;
    if (timeoutMs === undefined) {
      return handler(event);
    }

    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new WebhookHandlerTimeoutError(timeoutMs)),
        timeoutMs
      );
    });
    try {
      return await Promise.race([handler(event), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  /** Never throws: a broken logger must not take the request down with it. */
  private report(error: unknown, event?: WebhookEvent): void {
    const err = error instanceof Error ? error : new Error(String(error));
    const { onError } = this.options;
    if (!onError) {
      // Rejected requests are skipped: anyone can send them, so logging each
      // one would let unauthenticated callers flood the logs.
      if (!isRejection(err)) {
        console.error("[hookguard]", err);
      }
      return;
    }
    const logFailure = (failure: unknown) => {
      console.error("[hookguard] onError failed:", failure);
    };
    try {
      Promise.resolve(onError(err, event)).catch(logFailure);
    } catch (failure) {
      logFailure(failure);
    }
  }
}

function matches(pattern: string, eventType: string): boolean {
  if (pattern === "*" || pattern === eventType) {
    return true;
  }
  if (pattern.endsWith(".*")) {
    return eventType.startsWith(pattern.slice(0, -1));
  }
  return false;
}

function isRejection(error: unknown): boolean {
  return (
    error instanceof WebhookSignatureError ||
    error instanceof WebhookTimestampError ||
    error instanceof MissingHeaderError ||
    error instanceof WebhookPayloadError
  );
}

// Messages stay generic: callers are unauthenticated, and details belong in
// onError.
function failureResponse(error: unknown): WebhookResponse {
  if (error instanceof WebhookPayloadError) {
    return { status: 400, body: { error: "Invalid webhook payload" } };
  }
  if (isRejection(error)) {
    return { status: 401, body: { error: "Invalid webhook" } };
  }
  return PROCESSING_FAILED;
}

function defaultResponse(provider: ProviderName): WebhookResponse {
  return provider === "twilio"
    ? TWILIO_EMPTY_RESPONSE
    : { body: { received: true } };
}

function handshakeResponse(event: WebhookEvent): WebhookResponse | undefined {
  if (event.provider === "slack" && event.type === "url_verification") {
    return { body: { challenge: event.payload.challenge } };
  }
  if (event.provider === "discord" && event.payload.type === 1) {
    return { body: { type: 1 } };
  }
  return undefined;
}

function sendResponse(res: HttpResponseLike, response: WebhookResponse): void {
  if (response.contentType) {
    res.setHeader?.("Content-Type", response.contentType);
  }
  const sender = res.status(response.status ?? 200);
  if (typeof response.body === "string" && sender.send) {
    sender.send(response.body);
  } else {
    sender.json(response.body);
  }
}

/**
 * Prefers the provider's ID, unless it arrives in an unsigned header: changing
 * that would slip a replay past the check, so those deliveries use a body hash.
 */
function idempotencyKey(event: WebhookEvent): string {
  if (event.id !== undefined && !event.unsignedFields.includes("id")) {
    return `${event.provider}:${event.id}`;
  }
  const digest = createHash("sha256").update(event.rawBody).digest("hex");
  return `${event.provider}:sha256:${digest}`;
}

/**
 * The URL comes from configuration rather than Host or the request line, which
 * a client controls. Only the query string is taken from the request, because
 * Twilio adds a per-request bodySHA256 parameter.
 */
function resolveUrl(config: ProviderConfig, req: HttpRequestLike): string | undefined {
  if (config.url === undefined || config.url.includes("?")) {
    return config.url;
  }
  const target = req.originalUrl ?? req.url ?? "";
  const queryStart = target.indexOf("?");
  return queryStart === -1 ? config.url : config.url + target.slice(queryStart);
}
