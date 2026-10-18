import { WebhookSignatureError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeHex, hmacDigest } from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import {
  asEventHeaders,
  assertFreshTimestamp,
  parseJsonObject,
} from "../utils/request.js";

export function verifyStripe(
  request: NormalizedRequest,
  secret: string,
  options: VerifyOptions
): void {
  const header = requireHeader(request.headers, "stripe-signature");
  const timestamp = parseStripeTimestamp(header);
  assertFreshTimestamp(timestamp, options);

  const signedPayload = Buffer.concat([
    Buffer.from(`${timestamp}.`, "utf8"),
    request.rawBody,
  ]);
  const expected = hmacDigest("sha256", secret, signedPayload);
  const signatures = parseStripeSignatures(header);

  const matched = signatures.some((signature) => {
    try {
      return assertSafeEqualSilent(expected, decodeHex(signature, 32));
    } catch {
      return false;
    }
  });

  if (!matched) {
    throw new WebhookSignatureError("Stripe signature does not match");
  }
}

export function parseStripeEvent(request: NormalizedRequest): WebhookEvent {
  const payload = parseJsonObject(request.rawBodyText);
  return {
    provider: "stripe",
    type: stringField(payload, "type") ?? "unknown",
    payload,
    rawBody: request.rawBodyText,
    headers: asEventHeaders(request.headers),
    timestamp: new Date(),
    verified: true,
  };
}

function parseStripeTimestamp(header: string): number {
  for (const part of header.split(",")) {
    const [key, ...rest] = part.split("=");
    if (key === "t") {
      const timestamp = Number.parseInt(rest.join("="), 10);
      if (Number.isNaN(timestamp)) {
        throw new WebhookSignatureError("Stripe timestamp is malformed");
      }
      return timestamp;
    }
  }
  throw new WebhookSignatureError("Stripe signature header is missing timestamp");
}

function parseStripeSignatures(header: string): string[] {
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const [key, ...rest] = part.split("=");
    if (key === "v1" && rest.length > 0) {
      signatures.push(rest.join("="));
    }
  }
  if (signatures.length === 0) {
    throw new WebhookSignatureError("Stripe signature header is missing v1");
  }
  return signatures;
}

function assertSafeEqualSilent(expected: Buffer, received: Buffer): boolean {
  try {
    assertSafeEqual(expected, received);
    return true;
  } catch {
    return false;
  }
}

function stringField(
  payload: Record<string, unknown>,
  key: string
): string | undefined {
  const value = payload[key];
  return typeof value === "string" ? value : undefined;
}
