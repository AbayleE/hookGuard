import { WebhookConfigurationError, WebhookSignatureError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeBase64, hmacDigest } from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import {
  asEventHeaders,
  assertFreshTimestamp,
  parseJsonObject,
} from "../utils/request.js";

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
    Buffer.from(`${method}${url}`, "utf8"),
    request.rawBody,
    Buffer.from(timestampHeader, "utf8"),
  ]);
  const expected = hmacDigest("sha256", secret, source);
  const signature = requireHeader(request.headers, "x-hubspot-signature-v3");
  const received = decodeBase64(signature, 32);
  assertSafeEqual(expected, received, "HubSpot v3 signature does not match");
}

export function parseHubSpotEvent(request: NormalizedRequest): WebhookEvent {
  const payload = parseJsonObject(request.rawBodyText);
  const type =
    pickString(payload, "subscriptionType") ??
    pickString(payload, "eventType") ??
    "unknown";

  return {
    provider: "hubspot",
    type,
    payload,
    rawBody: request.rawBodyText,
    headers: asEventHeaders(request.headers),
    timestamp: new Date(),
    verified: true,
  };
}

function pickString(
  payload: Record<string, unknown>,
  key: string
): string | undefined {
  const value = payload[key];
  return typeof value === "string" ? value : undefined;
}
