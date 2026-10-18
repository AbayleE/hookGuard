import { WebhookSignatureError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeHex, hmacDigest } from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import {
  asEventHeaders,
  assertFreshTimestamp,
  parseJsonObject,
} from "../utils/request.js";

export function verifySlack(
  request: NormalizedRequest,
  secret: string,
  options: VerifyOptions
): void {
  const timestampHeader = requireHeader(
    request.headers,
    "x-slack-request-timestamp"
  );
  const timestamp = Number.parseInt(timestampHeader, 10);
  if (Number.isNaN(timestamp)) {
    throw new WebhookSignatureError("Slack timestamp is malformed");
  }
  assertFreshTimestamp(timestamp, options);

  const signature = requireHeader(request.headers, "x-slack-signature");
  if (!signature.startsWith("v0=")) {
    throw new WebhookSignatureError("Slack signature must be prefixed with v0=");
  }

  const basestring = Buffer.concat([
    Buffer.from(`v0:${timestampHeader}:`, "utf8"),
    request.rawBody,
  ]);
  const expected = hmacDigest("sha256", secret, basestring);
  const received = decodeHex(signature.slice(3), 32);
  assertSafeEqual(expected, received, "Slack signature does not match");
}

export function parseSlackEvent(request: NormalizedRequest): WebhookEvent {
  const payload = parseJsonObject(request.rawBodyText);
  const nested = payload.event;
  const nestedType =
    nested && typeof nested === "object" && !Array.isArray(nested)
      ? (nested as Record<string, unknown>).type
      : undefined;

  const type =
    (typeof nestedType === "string" ? nestedType : undefined) ??
    (typeof payload.type === "string" ? payload.type : undefined) ??
    "unknown";

  return {
    provider: "slack",
    type,
    payload,
    rawBody: request.rawBodyText,
    headers: asEventHeaders(request.headers),
    timestamp: new Date(),
    verified: true,
  };
}
