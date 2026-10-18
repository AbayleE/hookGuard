import { WebhookConfigurationError, WebhookPayloadError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeBase64, hmacDigest } from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import { asEventHeaders, parseFormBody } from "../utils/request.js";

export function verifyTwilio(
  request: NormalizedRequest,
  secret: string,
  options: VerifyOptions
): void {
  const signature = requireHeader(request.headers, "x-twilio-signature");
  const url = options.url ?? request.url;
  if (!url) {
    throw new WebhookConfigurationError(
      "Twilio verification requires the full webhook URL (options.url)"
    );
  }

  const signedString = buildTwilioSignedString(url, request);
  const expected = hmacDigest("sha1", secret, Buffer.from(signedString, "utf8"));
  const received = decodeBase64(signature, 20);
  assertSafeEqual(expected, received, "Twilio signature does not match");
}

export function parseTwilioEvent(request: NormalizedRequest): WebhookEvent {
  const payload = isJsonContent(request)
    ? parseLooseJson(request.rawBodyText)
    : parseFormBody(request.rawBodyText);

  const type =
    pickString(payload, "MessageStatus") ??
    pickString(payload, "CallStatus") ??
    pickString(payload, "EventType") ??
    "unknown";

  return {
    provider: "twilio",
    type,
    payload,
    rawBody: request.rawBodyText,
    headers: asEventHeaders(request.headers),
    timestamp: new Date(),
    verified: true,
  };
}

function buildTwilioSignedString(url: string, request: NormalizedRequest): string {
  if (isJsonContent(request)) {
    return url + request.rawBodyText;
  }

  const params = new URLSearchParams(request.rawBodyText);
  const keys = Array.from(new Set(params.keys())).sort();
  let signed = url;
  for (const key of keys) {
    signed += key + (params.get(key) ?? "");
  }
  return signed;
}

function isJsonContent(request: NormalizedRequest): boolean {
  const contentType = (request.contentType ?? "").toLowerCase();
  if (contentType.includes("application/json")) {
    return true;
  }
  if (contentType.includes("application/x-www-form-urlencoded")) {
    return false;
  }
  const trimmed = request.rawBodyText.trim();
  return trimmed.startsWith("{") || trimmed.startsWith("[");
}

function parseLooseJson(rawBodyText: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(rawBodyText);
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return { data: parsed };
  } catch {
    throw new WebhookPayloadError("Twilio JSON body could not be parsed");
  }
}

function pickString(
  payload: Record<string, unknown>,
  key: string
): string | undefined {
  const value = payload[key];
  return typeof value === "string" ? value : undefined;
}
