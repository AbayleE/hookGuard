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

export type HashAlgorithm = "sha1" | "sha256" | "sha512";

export type HeaderValue = string | string[] | undefined;

export type IncomingHeaders = Record<string, HeaderValue>;

export type RawBody = string | Buffer;

export interface WebhookRequest {
  body: RawBody;
  headers: IncomingHeaders;
  method?: string;
  url?: string;
}

export interface VerifyOptions {
  /**
   * Maximum age of a timestamped webhook, in seconds.
   * Used by Stripe, Slack, HubSpot, Clerk, and Discord replay protection.
   * @default 300
   */
  tolerance?: number;
  /**
   * Override "now" for deterministic tests. Unix seconds or a Date.
   */
  now?: number | Date;
  /**
   * Full webhook URL (scheme + host + path + query). Required for Twilio
   * and HubSpot v3.
   */
  url?: string;
  /**
   * HTTP method as received. Required for HubSpot v3. Defaults to POST.
   */
  method?: string;
  /**
   * Content-Type override when the header is missing. Affects Twilio.
   */
  contentType?: string;
  /**
   * HMAC algorithm for Zoho. Falls back to SHA-256 when omitted.
   */
  algorithm?: HashAlgorithm;
}

export interface WebhookEvent<TPayload = Record<string, unknown>> {
  provider: ProviderName;
  type: string;
  payload: TPayload;
  rawBody: string;
  headers: Record<string, string>;
  timestamp: Date;
  verified: true;
}

export interface ProviderConfig {
  secret: string;
  url?: string;
  algorithm?: HashAlgorithm;
  tolerance?: number;
}

export interface HookGuardOptions {
  providers: Partial<Record<ProviderName, ProviderConfig>>;
  onError?: (err: Error, event?: WebhookEvent) => void;
}

export type WebhookHandler = (event: WebhookEvent) => void | Promise<void>;

export interface NormalizedRequest {
  rawBody: Buffer;
  rawBodyText: string;
  headers: IncomingHeaders;
  method: string;
  url?: string;
  contentType?: string;
}

export const DEFAULT_TOLERANCE_SECONDS = 300;
