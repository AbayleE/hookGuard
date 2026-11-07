import { WebhookSignatureError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { decodeHex, hmacDigest, safeEqual } from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import {
  assertFreshTimestamp,
  createEvent,
  parseJsonObject,
  stringField,
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
      return safeEqual(expected, decodeHex(signature, 32));
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
  return createEvent(request, {
    provider: "stripe",
    type: stringField(payload, "type") ?? "unknown",
    id: stringField(payload, "id"),
    payload,
  });
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
