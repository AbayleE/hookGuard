import { WebhookSignatureError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { verifyEd25519 } from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import {
  asEventHeaders,
  assertFreshTimestamp,
  parseJsonObject,
} from "../utils/request.js";

export function verifyDiscord(
  request: NormalizedRequest,
  publicKey: string,
  options: VerifyOptions
): void {
  const signature = requireHeader(request.headers, "x-signature-ed25519");
  const timestampHeader = requireHeader(request.headers, "x-signature-timestamp");
  const timestamp = Number.parseInt(timestampHeader, 10);
  if (!Number.isNaN(timestamp)) {
    assertFreshTimestamp(timestamp, options);
  }

  const message = Buffer.concat([
    Buffer.from(timestampHeader, "utf8"),
    request.rawBody,
  ]);

  let valid = false;
  try {
    valid = verifyEd25519(message, signature, publicKey);
  } catch {
    throw new WebhookSignatureError("Discord Ed25519 signature is malformed");
  }

  if (!valid) {
    throw new WebhookSignatureError("Discord Ed25519 signature does not match");
  }
}

export function parseDiscordEvent(request: NormalizedRequest): WebhookEvent {
  const payload = parseJsonObject(request.rawBodyText);
  const type = payload.t ?? payload.type;

  return {
    provider: "discord",
    type: type === undefined ? "unknown" : String(type),
    payload,
    rawBody: request.rawBodyText,
    headers: asEventHeaders(request.headers),
    timestamp: new Date(),
    verified: true,
  };
}
