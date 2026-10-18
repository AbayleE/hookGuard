import { WebhookConfigurationError } from "./errors.js";
import type { IncomingHeaders, ProviderName, WebhookEvent, WebhookHandler, HookGuardOptions } from "./types.js";
import { constructEvent } from "./verify.js";

export interface HttpRequestLike {
  body: unknown;
  headers: IncomingHeaders;
  protocol?: string;
  originalUrl?: string;
  url?: string;
  method?: string;
  get?: (name: string) => string | undefined;
}

export interface HttpResponseLike {
  status(code: number): { json(body: unknown): unknown };
}

export type NextFunctionLike = (err?: unknown) => void;

export class HookGuard {
  private readonly handlers = new Map<string, WebhookHandler[]>();
  private readonly options: HookGuardOptions;

  constructor(options: HookGuardOptions) {
    this.options = options;
  }

  on(eventType: string, handler: WebhookHandler): this {
    const existing = this.handlers.get(eventType) ?? [];
    this.handlers.set(eventType, [...existing, handler]);
    return this;
  }

  constructEvent(provider: ProviderName, req: HttpRequestLike): WebhookEvent {
    const config = this.options.providers[provider];
    if (!config) {
      throw new WebhookConfigurationError(`Provider "${provider}" is not configured`);
    }

    return constructEvent(provider, extractBody(req), req.headers, config.secret, {
      url: config.url ?? inferUrl(req),
      method: req.method,
      algorithm: config.algorithm,
      tolerance: config.tolerance,
    });
  }

  middleware(provider: ProviderName) {
    return async (
      req: HttpRequestLike,
      res: HttpResponseLike,
      next: NextFunctionLike
    ): Promise<void> => {
      const config = this.options.providers[provider];
      if (!config) {
        res.status(400).json({ error: `Provider "${provider}" not configured` });
        return;
      }

      let event: WebhookEvent;
      try {
        event = this.constructEvent(provider, req);
      } catch (error) {
        res.status(401).json({
          error: error instanceof Error ? error.message : "Invalid webhook",
        });
        return;
      }

      res.status(200).json({ received: true });
      await this.dispatch(event);
      next();
    };
  }

  private async dispatch(event: WebhookEvent): Promise<void> {
    for (const [pattern, handlers] of this.handlers) {
      if (!matches(pattern, event.type)) {
        continue;
      }
      for (const handler of handlers) {
        try {
          await handler(event);
        } catch (err) {
          this.options.onError?.(err as Error, event);
        }
      }
    }
  }
}

function matches(pattern: string, eventType: string): boolean {
  if (pattern === eventType) {
    return true;
  }
  if (pattern.endsWith(".*")) {
    return eventType.startsWith(pattern.slice(0, -2));
  }
  return false;
}

function extractBody(req: HttpRequestLike): string | Buffer {
  if (typeof req.body === "string" || Buffer.isBuffer(req.body)) {
    return req.body;
  }
  if (req.body === undefined || req.body === null) {
    return "";
  }
  return JSON.stringify(req.body);
}

function inferUrl(req: HttpRequestLike): string | undefined {
  if (req.url?.startsWith("http://") || req.url?.startsWith("https://")) {
    return req.url;
  }
  const host = req.get?.("host");
  const path = req.originalUrl ?? req.url;
  if (!host || !path) {
    return undefined;
  }
  const protocol = req.protocol ?? "https";
  return `${protocol}://${host}${path}`;
}
