import { createHash } from "node:crypto";
import {
  WebhookConfigurationError,
  WebhookPayloadError,
  WebhookSignatureError,
} from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import {
  assertSafeEqual,
  decodeBase64,
  decodeHex,
  hmacDigest,
  safeEqual,
} from "../utils/crypto.js";
import { getHeader, requireHeader } from "../utils/headers.js";
import {
  createEvent,
  isRecord,
  parseFormBody,
  stringField,
} from "../utils/request.js";

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

  const isJson = isJsonContent(request);
  if (isJson) {
    // JSON webhooks: the signature covers the URL only. The URL must include
    // ?bodySHA256=<hex>, and that hash must match the actual body.
    assertTwilioBodyHash(url, request.rawBody);
  }

  const received = decodeBase64(signature, 20);
  const matched = urlVariants(url).some((candidate) => {
    const signed = isJson
      ? candidate
      : buildFormSignedString(candidate, request.rawBodyText);
    const expected = hmacDigest("sha1", secret, Buffer.from(signed, "utf8"));
    return safeEqual(expected, received);
  });

  if (!matched) {
    throw new WebhookSignatureError("Twilio signature does not match");
  }
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

// Every value of a repeated key is signed, de-duplicated and sorted, matching
// Twilio's SDK. Signing only one value would let extra values go unnoticed.
function buildFormSignedString(url: string, rawBodyText: string): string {
  const params = new URLSearchParams(rawBodyText);
  const keys = Array.from(new Set(params.keys())).sort();
  let signed = url;
  for (const key of keys) {
    for (const value of Array.from(new Set(params.getAll(key))).sort()) {
      signed += key + value;
    }
  }
  return signed;
}

/** Twilio may sign the URL with or without an explicit port, as its SDK allows. */
function urlVariants(url: string): string[] {
  const match = /^(https?):\/\/([^/?#:]+)(:\d+)?(.*)$/i.exec(url);
  if (!match) {
    return [url];
  }
  const [, scheme = "", host = "", port, rest = ""] = match;
  const base = `${scheme}://${host}`;
  const defaultPort = scheme.toLowerCase() === "https" ? ":443" : ":80";
  return Array.from(
    new Set([url, `${base}${rest}`, `${base}${port ?? defaultPort}${rest}`])
  );
}

function isJsonContent(request: NormalizedRequest): boolean {
  return (request.contentType ?? "").toLowerCase().includes("application/json");
}

export function parseTwilioEvent(request: NormalizedRequest): WebhookEvent {
  const payload = isJsonContent(request)
    ? parseLooseJson(request.rawBodyText)
    : parseFormBody(request.rawBodyText);

  const type =
    stringField(payload, "MessageStatus") ??
    stringField(payload, "CallStatus") ??
    stringField(payload, "EventType") ??
    "unknown";

  return createEvent(request, {
    provider: "twilio",
    type,
    id: getHeader(request.headers, "i-twilio-idempotency-token"),
    payload,
    unsignedFields: ["id"],
  });
}

function parseLooseJson(rawBodyText: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(rawBodyText);
    return isRecord(parsed) ? parsed : { data: parsed };
  } catch (error) {
    throw new WebhookPayloadError("Twilio JSON body could not be parsed", {
      cause: error,
    });
  }
}
