import { WebhookConfigurationError, WebhookSignatureError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { decodeBase64, hmacDigest, safeEqual } from "../utils/crypto.js";
import { getHeader, requireHeader } from "../utils/headers.js";
import {
  assertFreshTimestamp,
  createEvent,
  parseJsonObject,
  stringField,
} from "../utils/request.js";

export function verifyClerk(
  request: NormalizedRequest,
  secret: string,
  options: VerifyOptions
): void {
  const secretBytes = decodeClerkSecret(secret);
  const svixId = requireHeader(request.headers, "svix-id");
  const svixTimestamp = requireHeader(request.headers, "svix-timestamp");
  const svixSignature = requireHeader(request.headers, "svix-signature");

  const timestamp = Number.parseInt(svixTimestamp, 10);
  if (Number.isNaN(timestamp)) {
    throw new WebhookSignatureError("Clerk timestamp is malformed");
  }
  assertFreshTimestamp(timestamp, options);

  const signedContent = Buffer.concat([
    Buffer.from(`${svixId}.${svixTimestamp}.`, "utf8"),
    request.rawBody,
  ]);
  const expected = hmacDigest("sha256", secretBytes, signedContent);

  const matched = svixSignature.split(" ").some((part) => {
    const comma = part.indexOf(",");
    if (comma === -1) {
      return false;
    }
    const version = part.slice(0, comma);
    const value = part.slice(comma + 1);
    if (version !== "v1" || !value) {
      return false;
    }
    try {
      return safeEqual(expected, decodeBase64(value, 32));
    } catch {
      return false;
    }
  });

  if (!matched) {
    throw new WebhookSignatureError("Clerk/Svix signature does not match");
  }
}

/**
 * Node's base64 decoder skips invalid input, so a malformed secret can decode
 * to an empty key, which would let anyone compute a valid signature.
 */
export function decodeClerkSecret(secret: string): Buffer {
  const encoded = secret.replace(/^whsec_/, "");
  const key = Buffer.from(encoded, "base64");
  const roundTrip = key.toString("base64").replace(/=+$/, "");
  if (key.length === 0 || roundTrip !== encoded.replace(/=+$/, "")) {
    throw new WebhookConfigurationError(
      "Clerk webhook secret is not valid base64 (expected whsec_<base64>)"
    );
  }
  return key;
}

export function parseClerkEvent(request: NormalizedRequest): WebhookEvent {
  const payload = parseJsonObject(request.rawBodyText);
  return createEvent(request, {
    provider: "clerk",
    type: stringField(payload, "type") ?? "unknown",
    id: getHeader(request.headers, "svix-id"),
    payload,
  });
}
