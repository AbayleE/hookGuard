import { WebhookSignatureError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeBase64, hmacDigest } from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import {
  asEventHeaders,
  assertFreshTimestamp,
  parseJsonObject,
} from "../utils/request.js";

export function verifyClerk(
  request: NormalizedRequest,
  secret: string,
  options: VerifyOptions
): void {
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
  const secretBytes = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
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
      assertSafeEqual(expected, decodeBase64(value, 32));
      return true;
    } catch {
      return false;
    }
  });

  if (!matched) {
    throw new WebhookSignatureError("Clerk/Svix signature does not match");
  }
}

export function parseClerkEvent(request: NormalizedRequest): WebhookEvent {
  const payload = parseJsonObject(request.rawBodyText);
  return {
    provider: "clerk",
    type: typeof payload.type === "string" ? payload.type : "unknown",
    payload,
    rawBody: request.rawBodyText,
    headers: asEventHeaders(request.headers),
    timestamp: new Date(),
    verified: true,
  };
}
