import type { NormalizedRequest, VerifyOptions, WebhookEvent } from "../types.js";
import { assertSafeEqual, decodeBase64, hmacDigest } from "../utils/crypto.js";
import { requireHeader } from "../utils/headers.js";
import { asEventHeaders, parseJsonObject } from "../utils/request.js";

/** Zoho Sign: X-ZS-WEBHOOK-SIGNATURE = base64(HMAC-SHA256(rawBody, secret)). */
export function verifyZohoSign(
    request: NormalizedRequest,
    secret: string,
    options: VerifyOptions
): void {
    void options;
    const signature = requireHeader(request.headers, "x-zs-webhook-signature");
    const expected = hmacDigest("sha256", secret, request.rawBody);
    const received = decodeBase64(signature.trim(), 32);
    assertSafeEqual(expected, received, "Zoho Sign signature does not match");
}

export function parseZohoSignEvent(request: NormalizedRequest): WebhookEvent {
    const payload = parseJsonObject(request.rawBodyText);
    const notifications = payload.notifications;
    const operationType =
        notifications !== null &&
            typeof notifications === "object" &&
            !Array.isArray(notifications)
            ? (notifications as Record<string, unknown>).operation_type
            : undefined;

    return {
        provider: "zohosign",
        type: typeof operationType === "string" ? operationType : "unknown",
        payload,
        rawBody: request.rawBodyText,
        headers: asEventHeaders(request.headers),
        timestamp: new Date(),
        verified: true,
    };
}