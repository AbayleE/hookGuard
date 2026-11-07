// Zoho Billing webhook verification. Zoho Books shares the header but its
// signing scheme has not been confirmed against documentation.
import { WebhookConfigurationError, WebhookSignatureError } from "../errors.js";
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
import {
  createEvent,
  isFormContent,
  parseFormBody,
  parseJsonObject,
  stringField,
} from "../utils/request.js";

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
  const expected = hmacDigest(algorithm, secret, signedContent(request, options));
  const received = decodeZohoSignature(signature, DIGEST_BYTES[algorithm]);
  assertSafeEqual(expected, received, "Zoho signature does not match");
}

export function parseZohoEvent(request: NormalizedRequest): WebhookEvent {
  const payload = isFormContent(request)
    ? parseFormBody(request.rawBodyText)
    : parseJsonObject(request.rawBodyText);
  const type =
    stringField(payload, "event_type") ??
    stringField(payload, "event") ??
    stringField(payload, "status") ??
    "unknown";

  return createEvent(request, {
    provider: "zoho",
    type,
    id: stringField(payload, "event_id"),
    payload,
  });
}

/**
 * Query and form pairs sorted by key and joined as key + value, followed by the
 * raw JSON body. With neither kind of pair, that is just the raw body.
 */
function signedContent(request: NormalizedRequest, options: VerifyOptions): Buffer {
  const isForm = isFormContent(request);
  const pairs = queryPairs(options.url ?? request.url);
  if (isForm) {
    pairs.push(...new URLSearchParams(request.rawBodyText));
  }
  pairs.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  const prefix = Buffer.from(
    pairs.map(([key, value]) => key + value).join(""),
    "utf8"
  );
  return isForm ? prefix : Buffer.concat([prefix, request.rawBody]);
}

function queryPairs(url: string | undefined): [string, string][] {
  if (url === undefined) {
    return [];
  }
  try {
    return [...new URL(url).searchParams];
  } catch {
    throw new WebhookConfigurationError("Zoho webhook URL must be an absolute URL");
  }
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
