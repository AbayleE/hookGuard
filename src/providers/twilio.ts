import { createHash } from "crypto";
import { WebhookConfigurationError, WebhookPayloadError, WebhookSignatureError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeBase64, decodeHex, hmacDigest } from "../utils/crypto.js";
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

  let signedString: string;
  if (isJsonContent(request)) {
    // JSON webhooks: the signature covers the URL only. The URL must include
    // ?bodySHA256=<hex>, and that hash must match the actual body.
    assertTwilioBodyHash(url, request.rawBody);
    signedString = url;
  } else {
    signedString = buildFormSignedString(url, request.rawBodyText);
  }

  const expected = hmacDigest("sha1", secret, Buffer.from(signedString, "utf8"));
  const received = decodeBase64(signature, 20);
  assertSafeEqual(expected, received, "Twilio signature does not match");
}

function assertTwilioBodyHash(url: string, rawBody: Buffer): void {
  let claimed: string | null;
  try {
    claimed = new URL(url).searchParams.get("bodySHA256");
  } catch {
    throw new WebhookConfigurationError("Twilio webhook URL must be an absolute URL");
  }
  if (!claimed) {
    throw new WebhookSignatureError("Twilio JSON webhook URL is missing bodySHA256");
  }
  const actual = createHash("sha256").update(rawBody).digest();
  assertSafeEqual(actual, decodeHex(claimed, 32), "Twilio body hash does not match");
}

function buildFormSignedString(url: string, rawBodyText: string): string {
  const params = new URLSearchParams(rawBodyText);
  const keys = Array.from(new Set(params.keys())).sort();
  let signed = url;
  for (const key of keys) {
    signed += key + (params.get(key) ?? "");
  }
  return signed;
}


function isJsonContent(request: NormalizedRequest): boolean {
  return (request.contentType ?? "").toLowerCase().includes("application/json");
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
