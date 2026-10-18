import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeBase64, hmacDigest } from "../utils/crypto.js";
import { getHeader, requireHeader } from "../utils/headers.js";
import { asEventHeaders, parseJsonObject } from "../utils/request.js";

export function verifyShopify(
  request: NormalizedRequest,
  secret: string,
  options: VerifyOptions
): void {
  void options;
  const signature = requireHeader(request.headers, "x-shopify-hmac-sha256");
  const expected = hmacDigest("sha256", secret, request.rawBody);
  const received = decodeBase64(signature, 32);
  assertSafeEqual(expected, received, "Shopify HMAC does not match");
}

export function parseShopifyEvent(request: NormalizedRequest): WebhookEvent {
  const payload = parseJsonObject(request.rawBodyText);
  const topic = getHeader(request.headers, "x-shopify-topic") ?? "unknown";

  return {
    provider: "shopify",
    type: topic.replaceAll("/", "."),
    payload,
    rawBody: request.rawBodyText,
    headers: asEventHeaders(request.headers),
    timestamp: new Date(),
    verified: true,
  };
}
