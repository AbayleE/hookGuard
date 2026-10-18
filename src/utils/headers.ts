import { MissingHeaderError } from "../errors.js";
import type { HeaderValue, IncomingHeaders } from "../types.js";

export function getHeader(
  headers: IncomingHeaders,
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

export function requireHeader(headers: IncomingHeaders, name: string): string {
  const value = getHeader(headers, name);
  if (!value) {
    throw new MissingHeaderError(name);
  }
  return value;
}

export function flattenHeaders(headers: IncomingHeaders): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const first = firstHeaderValue(value);
    if (first !== undefined) {
      result[key.toLowerCase()] = first;
    }
  }
  return result;
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
