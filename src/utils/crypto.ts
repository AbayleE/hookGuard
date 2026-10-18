import { createHmac, createPublicKey, timingSafeEqual, verify } from "node:crypto";
import { WebhookSignatureError } from "../errors.js";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function hmacDigest(
  algorithm: string,
  secret: string | Buffer,
  data: Buffer
): Buffer {
  return createHmac(algorithm, secret).update(data).digest();
}

export function safeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

export function assertSafeEqual(a: Buffer, b: Buffer, message?: string): void {
  if (!safeEqual(a, b)) {
    throw new WebhookSignatureError(message);
  }
}

export function decodeHex(value: string, expectedBytes?: number): Buffer {
  const normalized = value.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new WebhookSignatureError("Signature is not valid hex");
  }
  const buffer = Buffer.from(normalized, "hex");
  if (expectedBytes !== undefined && buffer.length !== expectedBytes) {
    throw new WebhookSignatureError("Signature has unexpected length");
  }
  return buffer;
}

export function decodeBase64(value: string, expectedBytes?: number): Buffer {
  const compact = value.replace(/\s/g, "");
  const standard = compact.replace(/-/g, "+").replace(/_/g, "/");
  const buffer = Buffer.from(standard, "base64");
  if (expectedBytes !== undefined && buffer.length !== expectedBytes) {
    throw new WebhookSignatureError("Signature has unexpected length");
  }
  const roundTrip = buffer.toString("base64").replace(/=+$/, "");
  const normalized = standard.replace(/=+$/, "");
  if (buffer.length === 0 || roundTrip !== normalized) {
    throw new WebhookSignatureError("Signature is not valid base64");
  }
  return buffer;
}

export function verifyEd25519(
  message: Buffer,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  const signature = decodeHex(signatureHex, 64);
  const publicKeyRaw = decodeHex(publicKeyHex, 32);
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKeyRaw]),
    format: "der",
    type: "spki",
  });
  return verify(null, message, key, signature);
}
