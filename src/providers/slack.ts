import { WebhookSignatureError } from "../errors.js";
import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeHex, hmacDigest } from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import {
  assertFreshTimestamp,
  createEvent,
  isFormContent,
  isRecord,
  parseFormBody,
  parseJsonObject,
  stringField,
} from "../utils/request.js";

export function verifySlack(
  request: NormalizedRequest,
  secret: string,
  options: VerifyOptions
): void {
  const timestampHeader = requireHeader(
    request.headers,
    "x-slack-request-timestamp"
  );
  const timestamp = Number.parseInt(timestampHeader, 10);
  if (Number.isNaN(timestamp)) {
    throw new WebhookSignatureError("Slack timestamp is malformed");
  }
  assertFreshTimestamp(timestamp, options);

  const signature = requireHeader(request.headers, "x-slack-signature");
  if (!signature.startsWith("v0=")) {
    throw new WebhookSignatureError("Slack signature must be prefixed with v0=");
  }

  const basestring = Buffer.concat([
    Buffer.from(`v0:${timestampHeader}:`, "utf8"),
    request.rawBody,
  ]);
  const expected = hmacDigest("sha256", secret, basestring);
  const received = decodeHex(signature.slice(3), 32);
  assertSafeEqual(expected, received, "Slack signature does not match");
}

export function parseSlackEvent(request: NormalizedRequest): WebhookEvent {
  return isFormContent(request)
    ? parseSlackForm(request)
    : parseSlackJson(request);
}

function parseSlackJson(request: NormalizedRequest): WebhookEvent {
  const payload = parseJsonObject(request.rawBodyText);
  const nested = isRecord(payload.event)
    ? stringField(payload.event, "type")
    : undefined;

  return createEvent(request, {
    provider: "slack",
    type: nested ?? stringField(payload, "type") ?? "unknown",
    id: stringField(payload, "event_id"),
    payload,
  });
}

/** Slash commands are plain form fields; interactivity nests JSON in `payload`. */
function parseSlackForm(request: NormalizedRequest): WebhookEvent {
  const form = parseFormBody(request.rawBodyText);

  if (typeof form.payload === "string") {
    const payload = parseJsonObject(form.payload);
    return createEvent(request, {
      provider: "slack",
      type: stringField(payload, "type") ?? "unknown",
      id: stringField(payload, "trigger_id"),
      payload,
    });
  }

  return createEvent(request, {
    provider: "slack",
    type: typeof form.command === "string" ? "slash_command" : "unknown",
    id: stringField(form, "trigger_id"),
    payload: form,
  });
}
