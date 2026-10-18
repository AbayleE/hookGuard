import { WebhookSignatureError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeHex, hmacDigest } from "../utils/crypto.js";
import { getHeader, requireHeader } from "../utils/headers.js";
import { asEventHeaders, parseJsonObject } from "../utils/request.js";

export function verifyGitHub(
  request: NormalizedRequest,
  secret: string,
  options: VerifyOptions
): void {
  void options;
  const sha256 = getHeader(request.headers, "x-hub-signature-256");
  if (sha256) {
    const received = parsePrefixedSignature(sha256, "sha256", 32);
    const expected = hmacDigest("sha256", secret, request.rawBody);
    assertSafeEqual(expected, received, "GitHub SHA-256 signature does not match");
    return;
  }

  const sha1 = requireHeader(request.headers, "x-hub-signature");
  const received = parsePrefixedSignature(sha1, "sha1", 20);
  const expected = hmacDigest("sha1", secret, request.rawBody);
  assertSafeEqual(expected, received, "GitHub SHA-1 signature does not match");
}

export function parseGitHubEvent(request: NormalizedRequest): WebhookEvent {
  const payload = parseJsonObject(request.rawBodyText);
  const eventType = getHeader(request.headers, "x-github-event") ?? "unknown";
  const action = typeof payload.action === "string" ? payload.action : "";

  return {
    provider: "github",
    type: action ? `${eventType}.${action}` : eventType,
    payload,
    rawBody: request.rawBodyText,
    headers: asEventHeaders(request.headers),
    timestamp: new Date(),
    verified: true,
  };
}

function parsePrefixedSignature(
  header: string,
  algorithm: "sha256" | "sha1",
  expectedBytes: number
): Buffer {
  const prefix = `${algorithm}=`;
  if (!header.startsWith(prefix)) {
    throw new WebhookSignatureError(
      `GitHub signature must be prefixed with ${prefix}`
    );
  }
  return decodeHex(header.slice(prefix.length), expectedBytes);
}
