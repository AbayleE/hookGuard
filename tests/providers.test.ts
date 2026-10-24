import { createHash, createHmac, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  buildWebhookEvent,
  constructEvent,
  MissingHeaderError,
  UnsupportedProviderError,
  verifyWebhook,
  WebhookConfigurationError,
  WebhookSignatureError,
  WebhookTimestampError,
} from "../src/index.js";

const SECRET = "whsec_test_secret";
const NOW = 1_700_000_000;

function hmac(
  algorithm: string,
  secret: string | Buffer,
  data: string | Buffer,
  encoding: "hex" | "base64"
): string {
  return createHmac(algorithm, secret).update(data).digest(encoding);
}

describe("constructEvent / buildWebhookEvent", () => {
  it("are the same function and both verify a Stripe event", () => {
    expect(buildWebhookEvent).toBe(constructEvent);

    const body = JSON.stringify({ type: "payment_intent.succeeded", id: "evt_1" });
    const signature = hmac("sha256", SECRET, `${NOW}.${body}`, "hex");
    const headers = {
      "Stripe-Signature": `t=${NOW},v1=${signature}`,
    };

    const event = constructEvent("stripe", body, headers, SECRET, { now: NOW });
    const alias = buildWebhookEvent("stripe", { body, headers }, SECRET, {
      now: NOW,
    });

    expect(event.verified).toBe(true);
    expect(event.provider).toBe("stripe");
    expect(event.type).toBe("payment_intent.succeeded");
    expect(alias.type).toBe(event.type);
  });

  it("accepts Buffer bodies and case-insensitive headers", () => {
    const body = JSON.stringify({ type: "charge.succeeded" });
    const signature = hmac("sha256", SECRET, `${NOW}.${body}`, "hex");

    const event = constructEvent(
      "stripe",
      Buffer.from(body, "utf8"),
      { "STRIPE-SIGNATURE": `t=${NOW},v1=${signature}` },
      SECRET,
      { now: NOW }
    );

    expect(event.type).toBe("charge.succeeded");
    expect(event.rawBody).toBe(body);
  });

  it("throws UnsupportedProviderError for unknown providers", () => {
    expect(() =>
      constructEvent("paypal" as "stripe", "{}", {}, SECRET)
    ).toThrow(UnsupportedProviderError);
  });
});

describe("stripe", () => {
  const body = JSON.stringify({ type: "invoice.paid" });

  it("accepts any matching v1 signature when multiple are present", () => {
    const valid = hmac("sha256", SECRET, `${NOW}.${body}`, "hex");
    const headers = {
      "stripe-signature": `t=${NOW},v1=${"ab".repeat(32)},v1=${valid}`,
    };
    expect(constructEvent("stripe", body, headers, SECRET, { now: NOW }).type).toBe(
      "invoice.paid"
    );
  });

  it("rejects an invalid signature", () => {
    expect(() =>
      constructEvent(
        "stripe",
        body,
        { "stripe-signature": `t=${NOW},v1=${"ab".repeat(32)}` },
        SECRET,
        { now: NOW }
      )
    ).toThrow(WebhookSignatureError);
  });

  it("rejects replayed timestamps outside the 5-minute window", () => {
    const timestamp = NOW - 301;
    const signature = hmac("sha256", SECRET, `${timestamp}.${body}`, "hex");
    expect(() =>
      constructEvent(
        "stripe",
        body,
        { "stripe-signature": `t=${timestamp},v1=${signature}` },
        SECRET,
        { now: NOW }
      )
    ).toThrow(WebhookTimestampError);
  });

  it("rejects missing stripe-signature headers", () => {
    expect(() => constructEvent("stripe", body, {}, SECRET)).toThrow(
      MissingHeaderError
    );
  });
});

describe("github", () => {
  const body = JSON.stringify({ action: "opened", number: 1 });

  it("validates x-hub-signature-256 (HMAC-SHA256)", () => {
    const digest = hmac("sha256", SECRET, body, "hex");
    const event = constructEvent(
      "github",
      body,
      {
        "x-hub-signature-256": `sha256=${digest}`,
        "x-github-event": "pull_request",
      },
      SECRET
    );
    expect(event.type).toBe("pull_request.opened");
  });

  it("falls back to x-hub-signature (HMAC-SHA1)", () => {
    const pushBody = JSON.stringify({ ref: "refs/heads/main" });
    const digest = hmac("sha1", SECRET, pushBody, "hex");
    const event = constructEvent(
      "github",
      pushBody,
      {
        "X-Hub-Signature": `sha1=${digest}`,
        "X-GitHub-Event": "push",
      },
      SECRET
    );
    expect(event.type).toBe("push");
  });

  it("rejects a tampered body", () => {
    const digest = hmac("sha256", SECRET, body, "hex");
    expect(() =>
      constructEvent(
        "github",
        JSON.stringify({ action: "closed" }),
        { "x-hub-signature-256": `sha256=${digest}` },
        SECRET
      )
    ).toThrow(WebhookSignatureError);
  });
});

describe("shopify", () => {
  const body = JSON.stringify({ id: 11, name: "#1001" });

  it("validates base64 HMAC-SHA256 of the raw body", () => {
    const digest = hmac("sha256", SECRET, body, "base64");
    const event = constructEvent(
      "shopify",
      body,
      {
        "x-shopify-hmac-sha256": digest,
        "x-shopify-topic": "orders/paid",
      },
      SECRET
    );
    expect(event.type).toBe("orders.paid");
  });

  it("rejects an invalid HMAC", () => {
    expect(() =>
      constructEvent(
        "shopify",
        body,
        { "x-shopify-hmac-sha256": hmac("sha256", "wrong", body, "base64") },
        SECRET
      )
    ).toThrow(WebhookSignatureError);
  });
});

describe("slack", () => {
  const body = JSON.stringify({
    type: "event_callback",
    event: { type: "message" },
  });

  it("validates v0 HMAC-SHA256 over v0:timestamp:body", () => {
    const basestring = `v0:${NOW}:${body}`;
    const signature = `v0=${hmac("sha256", SECRET, basestring, "hex")}`;
    const event = constructEvent(
      "slack",
      body,
      {
        "x-slack-request-timestamp": String(NOW),
        "x-slack-signature": signature,
      },
      SECRET,
      { now: NOW }
    );
    expect(event.type).toBe("message");
  });

  it("rejects replayed Slack requests", () => {
    const timestamp = NOW - 400;
    const basestring = `v0:${timestamp}:${body}`;
    const signature = `v0=${hmac("sha256", SECRET, basestring, "hex")}`;
    expect(() =>
      constructEvent(
        "slack",
        body,
        {
          "x-slack-request-timestamp": String(timestamp),
          "x-slack-signature": signature,
        },
        SECRET,
        { now: NOW }
      )
    ).toThrow(WebhookTimestampError);
  });
});

describe("zoho", () => {
  const body = JSON.stringify({ event_type: "RequestSigned" });

  it("defaults to HMAC-SHA256 of the raw body", () => {
    const event = constructEvent(
      "zoho",
      body,
      { "x-zoho-webhook-signature": hmac("sha256", SECRET, body, "hex") },
      SECRET
    );
    expect(event.type).toBe("RequestSigned");
  });

  it("uses a configured algorithm when provided", () => {
    const event = constructEvent(
      "zoho",
      body,
      { "x-zoho-webhook-signature": hmac("sha1", SECRET, body, "hex") },
      SECRET,
      { algorithm: "sha1" }
    );
    expect(event.verified).toBe(true);
  });

  it("rejects SHA-1 signatures when SHA-256 is expected", () => {
    expect(() =>
      constructEvent(
        "zoho",
        body,
        { "x-zoho-webhook-signature": hmac("sha1", SECRET, body, "hex") },
        SECRET
      )
    ).toThrow(WebhookSignatureError);
  });
});

describe("twilio", () => {
  const url = "https://example.com/webhooks/twilio";

  it("signs sorted form parameters with HMAC-SHA1", () => {
    const body = "CallStatus=completed&From=%2B15551234567";
    const signed = `${url}CallStatuscompletedFrom+15551234567`;
    const signature = hmac("sha1", SECRET, signed, "base64");

    const event = constructEvent(
      "twilio",
      body,
      {
        "x-twilio-signature": signature,
        "content-type": "application/x-www-form-urlencoded",
      },
      SECRET,
      { url }
    );
    expect(event.type).toBe("completed");
    expect(event.payload.From).toBe("+15551234567");
  });

  it("requires the full webhook URL", () => {
    expect(() =>
      constructEvent(
        "twilio",
        "CallStatus=ringing",
        { "x-twilio-signature": hmac("sha1", SECRET, "x", "base64") },
        SECRET
      )
    ).toThrow(WebhookConfigurationError);
  });

  it("verifies JSON bodies via the bodySHA256 query parameter", () => {
    const body = JSON.stringify({ MessageStatus: "delivered" });
    const hash = createHash("sha256").update(body).digest("hex");
    const signedUrl = `${url}?bodySHA256=${hash}`;
    const signature = hmac("sha1", SECRET, signedUrl, "base64");
    const headers = { "x-twilio-signature": signature, "content-type": "application/json" };

    const event = constructEvent("twilio", body, headers, SECRET, { url: signedUrl });
    expect(event.type).toBe("delivered");
  });

  it("rejects a JSON body that doesn't match bodySHA256", () => {
    const body = JSON.stringify({ MessageStatus: "delivered" });
    const hash = createHash("sha256").update(body).digest("hex");
    const signedUrl = `${url}?bodySHA256=${hash}`;
    const signature = hmac("sha1", SECRET, signedUrl, "base64");

    expect(() =>
      constructEvent(
        "twilio",
        JSON.stringify({ MessageStatus: "failed" }),
        { "x-twilio-signature": signature, "content-type": "application/json" },
        SECRET,
        { url: signedUrl }
      )
    ).toThrow(WebhookSignatureError);
  });

  it("rejects JSON webhooks whose URL has no bodySHA256", () => {
    const body = JSON.stringify({ MessageStatus: "delivered" });
    const signature = hmac("sha1", SECRET, url, "base64");
    expect(() =>
      constructEvent(
        "twilio",
        body,
        { "x-twilio-signature": signature, "content-type": "application/json" },
        SECRET,
        { url }
      )
    ).toThrow(WebhookSignatureError);
  });
});

describe("hubspot", () => {
  const body = JSON.stringify({ subscriptionType: "contact.creation" });
  const url = "https://example.com/webhooks/hubspot";
  const method = "POST";
  const timestampMs = NOW * 1000;

  it("validates HMAC-SHA256 of method + uri + body + timestamp", () => {
    const source = `${method}${url}${body}${timestampMs}`;
    const signature = hmac("sha256", SECRET, source, "base64");
    const event = constructEvent(
      "hubspot",
      body,
      {
        "x-hubspot-signature-v3": signature,
        "x-hubspot-request-timestamp": String(timestampMs),
      },
      SECRET,
      { url, method, now: NOW }
    );
    expect(event.type).toBe("contact.creation");
  });

  it("rejects expired HubSpot timestamps", () => {
    const oldMs = (NOW - 400) * 1000;
    const source = `${method}${url}${body}${oldMs}`;
    const signature = hmac("sha256", SECRET, source, "base64");
    expect(() =>
      constructEvent(
        "hubspot",
        body,
        {
          "x-hubspot-signature-v3": signature,
          "x-hubspot-request-timestamp": String(oldMs),
        },
        SECRET,
        { url, method, now: NOW }
      )
    ).toThrow(WebhookTimestampError);
  });
});

describe("clerk", () => {
  const body = JSON.stringify({ type: "user.created" });
  const secretBytes = Buffer.from("clerk-secret-bytes");
  const secret = `whsec_${secretBytes.toString("base64")}`;
  const svixId = "msg_123";

  it("validates Svix-style signatures", () => {
    const signed = `${svixId}.${NOW}.${body}`;
    const digest = hmac("sha256", secretBytes, signed, "base64");
    const event = constructEvent(
      "clerk",
      body,
      {
        "svix-id": svixId,
        "svix-timestamp": String(NOW),
        "svix-signature": `v1,${digest}`,
      },
      secret,
      { now: NOW }
    );
    expect(event.type).toBe("user.created");
  });
});

describe("discord", () => {
  const body = JSON.stringify({ type: 1 });
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyHex = (publicKey.export({ type: "spki", format: "der" }) as Buffer)
    .subarray(-32)
    .toString("hex");

  it("validates Ed25519 signatures over timestamp + body", () => {
    const message = Buffer.from(`${NOW}${body}`, "utf8");
    const signature = sign(null, message, privateKey).toString("hex");
    const event = constructEvent(
      "discord",
      body,
      {
        "x-signature-ed25519": signature,
        "x-signature-timestamp": String(NOW),
      },
      publicKeyHex,
      { now: NOW }
    );
    expect(event.type).toBe("1");
  });

  it("rejects signatures from another key", () => {
    const other = generateKeyPairSync("ed25519");
    const message = Buffer.from(`${NOW}${body}`, "utf8");
    const signature = sign(null, message, other.privateKey).toString("hex");
    expect(() =>
      constructEvent(
        "discord",
        body,
        {
          "x-signature-ed25519": signature,
          "x-signature-timestamp": String(NOW),
        },
        publicKeyHex,
        { now: NOW }
      )
    ).toThrow(WebhookSignatureError);
  });
});

describe("zoho sign", () => {
  const body = JSON.stringify({
    requests: { request_name: "Test Name", request_id: "123" },
    notifications: { operation_type: "RequestSigningSuccess" },
  });

  it("validates the base64 HMAC-SHA256 of the raw body", () => {
    const event = constructEvent(
      "zohosign",
      body,
      { "X-ZS-WEBHOOK-SIGNATURE": hmac("sha256", SECRET, body, "base64") },
      SECRET
    );
    expect(event.provider).toBe("zohosign");
    expect(event.type).toBe("RequestSigningSuccess");
  });

  it("rejects a tampered body", () => {
    const signature = hmac("sha256", SECRET, body, "base64");
    expect(() =>
      constructEvent(
        "zohosign",
        body.replace("Test Name", "Evil Name"),
        { "x-zs-webhook-signature": signature },
        SECRET
      )
    ).toThrow(WebhookSignatureError);
  });

  it("rejects requests with no signature header (HMAC not enabled in Zoho)", () => {
    expect(() => constructEvent("zohosign", body, {}, SECRET)).toThrow(
      MissingHeaderError
    );
  });

  it("falls back to 'unknown' when operation_type is absent", () => {
    const plain = JSON.stringify({ hello: "world" });
    const event = constructEvent(
      "zohosign",
      plain,
      { "x-zs-webhook-signature": hmac("sha256", SECRET, plain, "base64") },
      SECRET
    );
    expect(event.type).toBe("unknown");
  });
});

describe("verifyWebhook", () => {
  it("returns false instead of throwing on invalid signatures", () => {
    expect(verifyWebhook("github", "{}", { "x-hub-signature-256": "sha256=00" }, SECRET)).toBe(
      false
    );
    expect(
      verifyWebhook(
        "github",
        "{}",
        { "x-hub-signature-256": `sha256=${hmac("sha256", SECRET, "{}", "hex")}` },
        SECRET
      )
    ).toBe(true);
  });
});
