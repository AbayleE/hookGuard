export const PROVIDERS = [
  "stripe",
  "github",
  "shopify",
  "slack",
  "twilio",
  "zoho",
  "zohosign",
  "hubspot",
  "clerk",
  "discord",
] as const;

export type ProviderName = (typeof PROVIDERS)[number];

export const HASH_ALGORITHMS = ["sha1", "sha256", "sha512"] as const;

export type HashAlgorithm = (typeof HASH_ALGORITHMS)[number];

export type HeaderValue = string | string[] | undefined;

export type HeaderRecord = Record<string, HeaderValue>;

/** Node-style header record, or a Fetch API `Headers` object. */
export type IncomingHeaders = HeaderRecord | Headers;

export type RawBody = string | Buffer | Uint8Array | ArrayBuffer;

/**
 * One secret, or several while rotating. A request passes if any of them
 * verifies it.
 */
export type WebhookSecret = string | readonly string[];

export interface WebhookRequest {
  body: RawBody;
  headers: IncomingHeaders;
  method?: string;
  url?: string;
}

export interface VerifyOptions {
  /**
   * Maximum age of a timestamped webhook, in seconds. Must be a finite number
   * of zero or more. Used by Stripe, Slack, HubSpot, Clerk, and Discord.
   * @default 300
   */
  tolerance?: number;
  /**
   * Override "now" for deterministic tests. Unix seconds or a Date.
   */
  now?: number | Date;
  /**
   * Full public webhook URL (scheme + host + path + query). Required for
   * Twilio and HubSpot, and for Zoho webhooks that use query parameters.
   */
  url?: string;
  /**
   * HTTP method as received. Used by HubSpot. Defaults to POST.
   */
  method?: string;
  /**
   * Content-Type override when the header is missing.
   */
  contentType?: string;
  /**
   * HMAC algorithm for Zoho. Falls back to SHA-256 when omitted.
   */
  algorithm?: HashAlgorithm;
  /**
   * Accept GitHub's legacy SHA-1 `x-hub-signature` header when the SHA-256
   * header is absent.
   * @default false
   */
  allowLegacySha1?: boolean;
}

/** Event fields taken from headers the provider does not sign. */
export type UnsignedField = "type" | "id";

export interface WebhookEvent<TPayload = Record<string, unknown>> {
  provider: ProviderName;
  type: string;
  /** The provider's identifier for this event or delivery, when it has one. */
  id?: string;
  payload: TPayload;
  rawBody: string;
  headers: Record<string, string>;
  /** When HookGuard processed the event. This is not a provider timestamp. */
  receivedAt: Date;
  verified: true;
  /**
   * Fields a holder of one captured request could change without invalidating
   * the signature. `payload` and `rawBody` are always covered by the signature.
   * `headers` is not, apart from the headers the provider's scheme signs.
   */
  unsignedFields: readonly UnsignedField[];
  /** One event per item, when the delivery is a batch (HubSpot). */
  batch?: readonly WebhookEvent<TPayload>[];
}

export interface ProviderConfig {
  secret: WebhookSecret;
  /**
   * Public URL of this webhook endpoint. Required for Twilio and HubSpot.
   * The query string of the incoming request is appended unless this URL
   * already has one.
   */
  url?: string;
  algorithm?: HashAlgorithm;
  tolerance?: number;
  allowLegacySha1?: boolean;
}

/** Records which deliveries were already processed. */
export interface IdempotencyStore {
  /**
   * Atomically record `key`. Return true if this is the first time it was
   * seen, and false if it was already claimed.
   */
  claim(key: string, event: WebhookEvent): boolean | Promise<boolean>;
  /**
   * Forget `key` after handlers fail, so the provider's retry is processed.
   */
  release?(key: string, event: WebhookEvent): void | Promise<void>;
}

export interface HookGuardOptions {
  providers: Partial<Record<ProviderName, ProviderConfig>>;
  /**
   * Called for rejected requests, handler failures, and store failures.
   * When omitted, everything except rejected requests goes to console.error.
   */
  onError?: (err: Error, event?: WebhookEvent) => void;
  /**
   * Fail a handler that runs longer than this. The handler is not cancelled;
   * HookGuard stops waiting for it.
   */
  handlerTimeoutMs?: number;
  /** Enables duplicate detection for deliveries. */
  idempotency?: IdempotencyStore;
}

/** A handler can return this to control the HTTP response. */
export interface WebhookResponse {
  status?: number;
  contentType?: string;
  body: unknown;
}

export type WebhookHandler<TPayload = Record<string, unknown>> = (
  event: WebhookEvent<TPayload>
) => void | WebhookResponse | Promise<void | WebhookResponse>;

export interface NormalizedRequest {
  rawBody: Buffer;
  rawBodyText: string;
  headers: HeaderRecord;
  method: string;
  url?: string;
  contentType?: string;
}

export const DEFAULT_TOLERANCE_SECONDS = 300;
