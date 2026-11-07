import {
  WebhookConfigurationError,
  WebhookPayloadError,
  WebhookSignatureError,
} from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeBase64, hmacDigest } from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import {
  assertFreshTimestamp,
  createEvent,
  isRecord,
  parseJsonValue,
  stringField,
} from "../utils/request.js";

/** The characters HubSpot decodes in the URI before signing. */
const SIGNED_URI_ESCAPES: Record<string, string> = {
  "%3A": ":",
  "%2F": "/",
  "%3F": "?",
  "%40": "@",
  "%21": "!",
  "%24": "$",
  "%27": "'",
  "%28": "(",
  "%29": ")",
  "%2A": "*",
  "%2C": ",",
  "%3B": ";",
};

export function verifyHubSpot(
  request: NormalizedRequest,
  secret: string,
  options: VerifyOptions
): void {
  const timestampHeader = requireHeader(
    request.headers,
    "x-hubspot-request-timestamp"
  );
  const timestampMs = Number.parseInt(timestampHeader, 10);
  if (Number.isNaN(timestampMs)) {
    throw new WebhookSignatureError("HubSpot timestamp is malformed");
  }
  assertFreshTimestamp(timestampMs, options, "ms");

  const url = options.url ?? request.url;
  if (!url) {
    throw new WebhookConfigurationError(
      "HubSpot v3 verification requires the request URI (options.url)"
    );
  }

  const method = (options.method ?? request.method).toUpperCase();
  const source = Buffer.concat([
    Buffer.from(`${method}${decodeSignedUri(url)}`, "utf8"),
    request.rawBody,
    Buffer.from(timestampHeader, "utf8"),
  ]);
  const expected = hmacDigest("sha256", secret, source);
  const signature = requireHeader(request.headers, "x-hubspot-signature-v3");
  const received = decodeBase64(signature, 32);
  assertSafeEqual(expected, received, "HubSpot v3 signature does not match");
}

function decodeSignedUri(url: string): string {
  return url.replace(
    /%[0-9a-f]{2}/gi,
    (escape) => SIGNED_URI_ESCAPES[escape.toUpperCase()] ?? escape
  );
}

/**
 * HubSpot delivers a JSON array of up to 100 events. A batch is returned as one
 * event with `payload.events`, and `batch` holds an event for each item.
 */
export function parseHubSpotEvent(request: NormalizedRequest): WebhookEvent {
  const parsed = parseJsonValue(request.rawBodyText);

  if (Array.isArray(parsed)) {
    const items = parsed.map(assertHubSpotItem);
    const batch = items.map((item) => itemEvent(request, item));
    const types = new Set(batch.map((event) => event.type));
    const [onlyType] = types;
    return {
      ...createEvent(request, {
        provider: "hubspot",
        type: types.size === 1 && onlyType !== undefined ? onlyType : "batch",
        payload: { events: items },
      }),
      batch,
    };
  }

  return itemEvent(request, assertHubSpotItem(parsed));
}

function assertHubSpotItem(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new WebhookPayloadError("HubSpot events must be JSON objects");
  }
  return value;
}

function itemEvent(
  request: NormalizedRequest,
  item: Record<string, unknown>
): WebhookEvent {
  const eventId = item.eventId;
  return createEvent(request, {
    provider: "hubspot",
    type:
      stringField(item, "subscriptionType") ??
      stringField(item, "eventType") ??
      "unknown",
    id:
      typeof eventId === "string" || typeof eventId === "number"
        ? String(eventId)
        : undefined,
    payload: item,
  });
}
