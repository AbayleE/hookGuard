import {
  MissingHeaderError,
  WebhookConfigurationError,
  WebhookSignatureError,
  WebhookTimestampError,
} from "./errors.js";
import { getProviderStrategy, type ProviderStrategy } from "./providers/index.js";
import type {
  IncomingHeaders,
  NormalizedRequest,
  ProviderConfig,
  ProviderName,
  RawBody,
  VerifyOptions,
  WebhookEvent,
  WebhookRequest,
  WebhookSecret,
} from "./types.js";
import { assertValidOptions, normalizeRequest } from "./utils/request.js";

const PROVIDERS_REQUIRING_URL: readonly string[] = ["twilio", "hubspot"];

export function constructEvent<TPayload = Record<string, unknown>>(
  provider: ProviderName,
  body: RawBody,
  headers: IncomingHeaders,
  secret: WebhookSecret,
  options?: VerifyOptions
): WebhookEvent<TPayload>;
export function constructEvent<TPayload = Record<string, unknown>>(
  provider: ProviderName,
  request: WebhookRequest,
  secret: WebhookSecret,
  options?: VerifyOptions
): WebhookEvent<TPayload>;
export function constructEvent(
  provider: ProviderName,
  bodyOrRequest: RawBody | WebhookRequest,
  headersOrSecret: IncomingHeaders | WebhookSecret,
  secretOrOptions?: WebhookSecret | VerifyOptions,
  maybeOptions?: VerifyOptions
): WebhookEvent {
  const { strategy, request } = verifyArgs(
    provider,
    bodyOrRequest,
    headersOrSecret,
    secretOrOptions,
    maybeOptions
  );
  return strategy.parse(request);
}

/**
 * Alias of {@link constructEvent}. Stripe-style naming is `constructEvent`;
 * some adapters prefer `buildWebhookEvent`.
 */
export const buildWebhookEvent: typeof constructEvent = constructEvent;

/**
 * Checks authenticity only: the payload is not parsed. Returns false for
 * signature, timestamp, and missing-header failures. Configuration mistakes
 * still throw, so they cannot be mistaken for a forged request.
 */
export function verifyWebhook(
  provider: ProviderName,
  body: RawBody,
  headers: IncomingHeaders,
  secret: WebhookSecret,
  options?: VerifyOptions
): boolean;
export function verifyWebhook(
  provider: ProviderName,
  request: WebhookRequest,
  secret: WebhookSecret,
  options?: VerifyOptions
): boolean;
export function verifyWebhook(
  provider: ProviderName,
  bodyOrRequest: RawBody | WebhookRequest,
  headersOrSecret: IncomingHeaders | WebhookSecret,
  secretOrOptions?: WebhookSecret | VerifyOptions,
  maybeOptions?: VerifyOptions
): boolean {
  try {
    verifyArgs(
      provider,
      bodyOrRequest,
      headersOrSecret,
      secretOrOptions,
      maybeOptions
    );
    return true;
  } catch (error) {
    if (
      error instanceof WebhookSignatureError ||
      error instanceof WebhookTimestampError ||
      error instanceof MissingHeaderError
    ) {
      return false;
    }
    throw error;
  }
}

/** Startup validation for a provider, used by the HookGuard constructor. */
export function assertValidProviderConfig(
  provider: string,
  config: ProviderConfig
): void {
  const strategy = getProviderStrategy(provider);
  const secrets = normalizeSecrets(config?.secret);
  for (const secret of secrets) {
    strategy.validateSecret?.(secret);
  }
  assertValidOptions(config);

  if (config.url === undefined) {
    if (PROVIDERS_REQUIRING_URL.includes(provider)) {
      throw new WebhookConfigurationError(
        `Provider "${provider}" requires its public webhook URL (providers.${provider}.url)`
      );
    }
  } else if (!URL.canParse(config.url)) {
    throw new WebhookConfigurationError(
      `Provider "${provider}" url must be an absolute URL`
    );
  }
}

function verifyArgs(
  provider: ProviderName,
  bodyOrRequest: RawBody | WebhookRequest,
  headersOrSecret: IncomingHeaders | WebhookSecret,
  secretOrOptions?: WebhookSecret | VerifyOptions,
  maybeOptions?: VerifyOptions
): { strategy: ProviderStrategy; request: NormalizedRequest } {
  const { body, headers, secret, options } = normalizeArgs(
    bodyOrRequest,
    headersOrSecret,
    secretOrOptions,
    maybeOptions
  );

  const secrets = normalizeSecrets(secret);
  assertValidOptions(options);
  const request = normalizeRequest(body, headers, options);
  const strategy = getProviderStrategy(provider);
  verifyWithSecrets(strategy, request, secrets, options);
  return { strategy, request };
}

function verifyWithSecrets(
  strategy: ProviderStrategy,
  request: NormalizedRequest,
  secrets: readonly string[],
  options: VerifyOptions
): void {
  let failure: WebhookSignatureError | undefined;
  for (const secret of secrets) {
    try {
      strategy.verify(request, secret, options);
      return;
    } catch (error) {
      if (!(error instanceof WebhookSignatureError)) {
        throw error;
      }
      failure = error;
    }
  }
  throw failure;
}

function normalizeSecrets(secret: unknown): readonly string[] {
  const secrets: unknown[] = Array.isArray(secret) ? secret : [secret];
  const valid =
    secrets.length > 0 &&
    secrets.every((value) => typeof value === "string" && value.length > 0);
  if (!valid) {
    throw new WebhookConfigurationError(
      "Webhook secret must be a non-empty string (is your env var set?)"
    );
  }
  return secrets as string[];
}

function normalizeArgs(
  bodyOrRequest: RawBody | WebhookRequest,
  headersOrSecret: IncomingHeaders | WebhookSecret,
  secretOrOptions?: WebhookSecret | VerifyOptions,
  maybeOptions?: VerifyOptions
): {
  body: RawBody;
  headers: IncomingHeaders;
  secret: WebhookSecret;
  options: VerifyOptions;
} {
  if (isWebhookRequest(bodyOrRequest)) {
    if (!isSecret(headersOrSecret)) {
      throw new WebhookConfigurationError(
        "constructEvent(provider, request, secret) requires a secret (is your env var set?)"
      );
    }
    const requestOptions =
      typeof secretOrOptions === "object" &&
      secretOrOptions !== null &&
      !isSecret(secretOrOptions)
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

  if (isSecret(headersOrSecret) || !isSecret(secretOrOptions)) {
    throw new WebhookConfigurationError(
      "constructEvent(provider, body, headers, secret) requires headers and a secret (is your env var set?)"
    );
  }

  return {
    body: bodyOrRequest,
    headers: headersOrSecret,
    secret: secretOrOptions,
    options: maybeOptions ?? {},
  };
}

function isSecret(value: unknown): value is WebhookSecret {
  return typeof value === "string" || Array.isArray(value);
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
