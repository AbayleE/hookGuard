import { WebhookConfigurationError, MissingHeaderError } from "../errors.js";
import type { HeaderRecord, HeaderValue, IncomingHeaders } from "../types.js";

export function toHeaderRecord(headers: IncomingHeaders): HeaderRecord {
  if (headers === null || typeof headers !== "object") {
    throw new WebhookConfigurationError("Webhook headers must be an object");
  }
  if (isFetchHeaders(headers)) {
    return Object.fromEntries(headers.entries());
  }
  return headers;
}

export function getHeader(
  headers: HeaderRecord,
  name: string
): string | undefined {
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) {
      return firstHeaderValue(value);
    }
  }
  return undefined;
}

export function requireHeader(headers: HeaderRecord, name: string): string {
  const value = getHeader(headers, name);
  if (!value) {
    throw new MissingHeaderError(name);
  }
  return value;
}

export function flattenHeaders(headers: HeaderRecord): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const first = firstHeaderValue(value);
    if (first !== undefined) {
      result[key.toLowerCase()] = first;
    }
  }
  return result;
}

// Duck-typed because frameworks may bring their own Headers implementation.
function isFetchHeaders(headers: IncomingHeaders): headers is Headers {
  const candidate = headers as Partial<Headers>;
  return (
    typeof candidate.get === "function" &&
    typeof candidate.entries === "function"
  );
}

function firstHeaderValue(value: HeaderValue): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}
