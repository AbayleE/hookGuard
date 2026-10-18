import { WebhookPayloadError, WebhookTimestampError } from "../errors.js";
import {
  DEFAULT_TOLERANCE_SECONDS,
  type IncomingHeaders,
  type NormalizedRequest,
  type RawBody,
  type VerifyOptions,
} from "../types.js";
import { flattenHeaders, getHeader } from "./headers.js";

export function normalizeRequest(
  body: RawBody,
  headers: IncomingHeaders,
  options: VerifyOptions = {}
): NormalizedRequest {
  const rawBody = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  const contentType = options.contentType ?? getHeader(headers, "content-type");

  return {
    rawBody,
    rawBodyText: rawBody.toString("utf8"),
    headers,
    method: (options.method ?? "POST").toUpperCase(),
    url: options.url,
    contentType,
  };
}

export function parseJsonObject(rawBodyText: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(rawBodyText);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new WebhookPayloadError("Webhook JSON payload must be an object");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof WebhookPayloadError) {
      throw error;
    }
    throw new WebhookPayloadError("Failed to parse webhook JSON payload");
  }
}

export function parseFormBody(rawBodyText: string): Record<string, unknown> {
  const params = new URLSearchParams(rawBodyText);
  const payload: Record<string, unknown> = {};
  for (const [key, value] of params.entries()) {
    payload[key] = value;
  }
  return payload;
}

export function unixNow(now?: number | Date): number {
  if (now === undefined) {
    return Math.floor(Date.now() / 1000);
  }
  if (now instanceof Date) {
    return Math.floor(now.getTime() / 1000);
  }
  return now > 1e12 ? Math.floor(now / 1000) : now;
}

export function asEventHeaders(headers: IncomingHeaders): Record<string, string> {
  return flattenHeaders(headers);
}

export function assertFreshTimestamp(
  timestampSeconds: number,
  options: VerifyOptions,
  unit: "s" | "ms" = "s"
): void {
  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE_SECONDS;
  const timestamp =
    unit === "ms" ? timestampSeconds / 1000 : timestampSeconds;

  if (!Number.isFinite(timestamp)) {
    throw new WebhookTimestampError("Webhook timestamp is malformed");
  }

  const age = Math.abs(unixNow(options.now) - timestamp);
  if (age > tolerance) {
    throw new WebhookTimestampError(
      `Webhook timestamp is ${Math.round(age)}s old (tolerance ${tolerance}s)`
    );
  }
}
