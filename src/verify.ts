import { HookGuardError, WebhookConfigurationError } from "./errors.js";
import { getProviderStrategy } from "./providers/index.js";
import type {
  IncomingHeaders,
  ProviderName,
  RawBody,
  VerifyOptions,
  WebhookEvent,
  WebhookRequest,
} from "./types.js";
import { normalizeRequest } from "./utils/request.js";

export function constructEvent(
  provider: ProviderName,
  body: RawBody,
  headers: IncomingHeaders,
  secret: string,
  options?: VerifyOptions
): WebhookEvent;
export function constructEvent(
  provider: ProviderName,
  request: WebhookRequest,
  secret: string,
  options?: VerifyOptions
): WebhookEvent;
export function constructEvent(
  provider: ProviderName,
  bodyOrRequest: RawBody | WebhookRequest,
  headersOrSecret: IncomingHeaders | string,
  secretOrOptions?: string | VerifyOptions,
  maybeOptions?: VerifyOptions
): WebhookEvent {
  const { body, headers, secret, options } = normalizeArgs(
    bodyOrRequest,
    headersOrSecret,
    secretOrOptions,
    maybeOptions
  );

  if (typeof secret !== "string" || secret.length === 0) {
    throw new WebhookConfigurationError(
      "Webhook secret must be a non-empty string (is your env var set?)"
    );
  }

  const request = normalizeRequest(body, headers, options);
  const strategy = getProviderStrategy(provider);
  strategy.verify(request, secret, options);
  return strategy.parse(request);
}

/**
 * Alias of {@link constructEvent}. Stripe-style naming is `constructEvent`;
 * some adapters prefer `buildWebhookEvent`.
 */
export const buildWebhookEvent: typeof constructEvent = constructEvent;

export function verifyWebhook(
  provider: ProviderName,
  body: RawBody,
  headers: IncomingHeaders,
  secret: string,
  options?: VerifyOptions
): boolean {
  try {
    constructEvent(provider, body, headers, secret, options);
    return true;
  } catch (error) {
    if (error instanceof WebhookConfigurationError) {
      throw error;
    }
    if (error instanceof HookGuardError) {
      return false;
    }
    throw error;
  }
}

function normalizeArgs(
  bodyOrRequest: RawBody | WebhookRequest,
  headersOrSecret: IncomingHeaders | string,
  secretOrOptions?: string | VerifyOptions,
  maybeOptions?: VerifyOptions
): {
  body: RawBody;
  headers: IncomingHeaders;
  secret: string;
  options: VerifyOptions;
} {
  if (isWebhookRequest(bodyOrRequest)) {
    if (typeof headersOrSecret !== "string") {
      throw new TypeError("constructEvent(request, secret) requires a secret string");
    }
    const requestOptions =
      typeof secretOrOptions === "object" && secretOrOptions !== null
        ? secretOrOptions
        : {};
    return {
      body: bodyOrRequest.body,
      headers: bodyOrRequest.headers,
      secret: headersOrSecret,
      options: {
        method: bodyOrRequest.method,
        url: bodyOrRequest.url,
        ...requestOptions,
      },
    };
  }

  if (typeof secretOrOptions !== "string" || typeof headersOrSecret === "string") {
    throw new TypeError("constructEvent(body, headers, secret) requires a secret string");
  }

  return {
    body: bodyOrRequest,
    headers: headersOrSecret,
    secret: secretOrOptions,
    options: maybeOptions ?? {},
  };
}

function isWebhookRequest(value: RawBody | WebhookRequest): value is WebhookRequest {
  return (
    typeof value === "object" &&
    value !== null &&
    !Buffer.isBuffer(value) &&
    "body" in value &&
    "headers" in value
  );
}
