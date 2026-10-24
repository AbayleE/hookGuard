//Zoho Books/Billing Webhook Verification
import { WebhookSignatureError } from "../errors.js";
import type {
  HashAlgorithm,
  NormalizedRequest,
  VerifyOptions,
  WebhookEvent,
} from "../types.js";
import {
  assertSafeEqual,
  decodeBase64,
  decodeHex,
  hmacDigest,
} from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import { asEventHeaders, parseJsonObject } from "../utils/request.js";

const DIGEST_BYTES: Record<HashAlgorithm, number> = {
  sha1: 20,
  sha256: 32,
  sha512: 64,
};

export function verifyZoho(
  request: NormalizedRequest,
  secret: string,
  options: VerifyOptions
): void {
  const signature = requireHeader(request.headers, "x-zoho-webhook-signature");
  const algorithm: HashAlgorithm = options.algorithm ?? "sha256";
  const expected = hmacDigest(algorithm, secret, request.rawBody);
  const received = decodeZohoSignature(signature, DIGEST_BYTES[algorithm]);
  assertSafeEqual(expected, received, "Zoho signature does not match");
}

export function parseZohoEvent(request: NormalizedRequest): WebhookEvent {
  const payload = parseJsonObject(request.rawBodyText);
  const type =
    pickString(payload, "event_type") ??
    pickString(payload, "event") ??
    pickString(payload, "status") ??
    "unknown";

  return {
    provider: "zoho",
    type,
    payload,
    rawBody: request.rawBodyText,
    headers: asEventHeaders(request.headers),
    timestamp: new Date(),
    verified: true,
  };
}

function decodeZohoSignature(signature: string, expectedBytes: number) {
  const trimmed = signature.trim();
  try {
    return decodeHex(trimmed, expectedBytes);
  } catch {
    try {
      return decodeBase64(trimmed, expectedBytes);
    } catch {
      throw new WebhookSignatureError("Zoho signature encoding is not recognized");
    }
  }
}

function pickString(
  payload: Record<string, unknown>,
  key: string
): string | undefined {
  const value = payload[key];
  return typeof value === "string" ? value : undefined;
}
