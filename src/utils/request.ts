import {
  WebhookConfigurationError,
  WebhookPayloadError,
  WebhookTimestampError,
} from "../errors.js";
import {
  DEFAULT_TOLERANCE_SECONDS,
  HASH_ALGORITHMS,
  type HashAlgorithm,
  type IncomingHeaders,
  type NormalizedRequest,
  type ProviderName,
  type RawBody,
  type UnsignedField,
  type VerifyOptions,
  type WebhookEvent,
} from "../types.js";
import { flattenHeaders, getHeader, toHeaderRecord } from "./headers.js";

export function normalizeRequest(
  body: RawBody,
  headers: IncomingHeaders,
  options: VerifyOptions = {}
): NormalizedRequest {
  const rawBody = toBuffer(body);
  const headerRecord = toHeaderRecord(headers);
  const contentType = options.contentType ?? getHeader(headerRecord, "content-type");

  return {
    rawBody,
    rawBodyText: rawBody.toString("utf8"),
    headers: headerRecord,
    method: (options.method ?? "POST").toUpperCase(),
    url: options.url,
    contentType,
  };
}

function toBuffer(body: RawBody): Buffer {
  if (typeof body === "string") {
    return Buffer.from(body, "utf8");
  }
  if (Buffer.isBuffer(body)) {
    return body;
  }
  if (body instanceof Uint8Array) {
    return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  }
  if (body instanceof ArrayBuffer) {
    return Buffer.from(body);
  }
  throw new WebhookConfigurationError(
    "Webhook body must be the raw, unparsed request body (string, Buffer, " +
      "Uint8Array, or ArrayBuffer). Signatures cover the exact bytes received, " +
      'so read it with a raw parser such as express.raw({ type: "*/*" }).'
  );
}

/** Rejects settings that would otherwise silently weaken verification. */
export function assertValidOptions(options: {
  tolerance?: number;
  algorithm?: HashAlgorithm;
}): void {
  const { tolerance, algorithm } = options;
  if (
    tolerance !== undefined &&
    !(typeof tolerance === "number" && Number.isFinite(tolerance) && tolerance >= 0)
  ) {
    throw new WebhookConfigurationError(
      `Webhook tolerance must be a finite number of seconds, 0 or more (received ${String(tolerance)})`
    );
  }
  if (algorithm !== undefined && !HASH_ALGORITHMS.includes(algorithm)) {
    throw new WebhookConfigurationError(
      `Unsupported HMAC algorithm: ${String(algorithm)}`
    );
  }
}

export function isFormContent(request: NormalizedRequest): boolean {
  return (request.contentType ?? "")
    .toLowerCase()
    .includes("application/x-www-form-urlencoded");
}

export function parseJsonValue(rawBodyText: string): unknown {
  try {
    return JSON.parse(rawBodyText);
  } catch (error) {
    throw new WebhookPayloadError("Failed to parse webhook JSON payload", {
      cause: error,
    });
  }
}

export function parseJsonObject(rawBodyText: string): Record<string, unknown> {
  const parsed = parseJsonValue(rawBodyText);
  if (!isRecord(parsed)) {
    throw new WebhookPayloadError("Webhook JSON payload must be an object");
  }
  return parsed;
}

/** Repeated keys become arrays, so no submitted value is hidden. */
export function parseFormBody(rawBodyText: string): Record<string, unknown> {
  const grouped = new Map<string, string[]>();
  for (const [key, value] of new URLSearchParams(rawBodyText)) {
    grouped.set(key, [...(grouped.get(key) ?? []), value]);
  }
  return Object.fromEntries(
    Array.from(grouped, ([key, values]) => [
      key,
      values.length === 1 ? values[0] : values,
    ])
  );
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function stringField(
  payload: Record<string, unknown>,
  key: string
): string | undefined {
  const value = payload[key];
  return typeof value === "string" ? value : undefined;
}

export function createEvent(
  request: NormalizedRequest,
  fields: {
    provider: ProviderName;
    type: string;
    payload: Record<string, unknown>;
    id?: string;
    unsignedFields?: readonly UnsignedField[];
  }
): WebhookEvent {
  return {
    provider: fields.provider,
    type: fields.type,
    id: fields.id,
    payload: fields.payload,
    rawBody: request.rawBodyText,
    headers: flattenHeaders(request.headers),
    receivedAt: new Date(),
    verified: true,
    unsignedFields: fields.unsignedFields ?? [],
  };
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
