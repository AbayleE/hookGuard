// One block per finding in package-docs/publishing_readiness_audit.md.
import { createHash, createHmac, generateKeyPairSync, sign } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  constructEvent,
  HookGuard,
  MissingHeaderError,
  UnsupportedProviderError,
  verifyWebhook,
  WebhookConfigurationError,
  WebhookHandlerTimeoutError,
  WebhookPayloadError,
  WebhookSignatureError,
  WebhookTimestampError,
  type HttpRequestLike,
  type IdempotencyStore,
  type ProviderName,
  type VerifyOptions,
} from "../src/index.js";

const SECRET = "test-secret";
const now = () => Math.floor(Date.now() / 1000);

afterEach(() => {
  vi.restoreAllMocks();
});

function fakeRes() {
  const res = {
    statusCode: 0,
    body: undefined as unknown,
    headers: {} as Record<string, string>,
    setHeader(name: string, value: string) {
      res.headers[name] = value;
    },
    status(code: number) {
      res.statusCode = code;
      return {
        json(body: unknown) {
          res.body = body;
        },
        send(body: unknown) {
          res.body = body;
        },
      };
    },
  };
  return res;
}

async function deliver(
  guard: HookGuard,
  provider: ProviderName,
  req: HttpRequestLike,
  options?: Parameters<HookGuard["middleware"]>[1]
) {
  const res = fakeRes();
  const next = vi.fn();
  await guard.middleware(provider, options)(req, res, next);
  return { res, next };
}

function github(payload: object, event = "push", extra: Record<string, string> = {}) {
  const body = JSON.stringify(payload);
  const digest = createHmac("sha256", SECRET).update(body).digest("hex");
  return {
    body: Buffer.from(body),
    headers: {
      "x-hub-signature-256": `sha256=${digest}`,
      "x-github-event": event,
      ...extra,
    },
  };
}

function githubGuard(options: Partial<ConstructorParameters<typeof HookGuard>[0]> = {}) {
  return new HookGuard({ providers: { github: { secret: SECRET } }, ...options });
}

function stripe(body: string, secret = SECRET, timestamp = now()) {
  const digest = createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
  return { "stripe-signature": `t=${timestamp},v1=${digest}` };
}

function slack(body: string, contentType: string) {
  const timestamp = String(now());
  const digest = createHmac("sha256", SECRET).update(`v0:${timestamp}:${body}`).digest("hex");
  return {
    body: Buffer.from(body),
    headers: {
      "x-slack-signature": `v0=${digest}`,
      "x-slack-request-timestamp": timestamp,
      "content-type": contentType,
    },
  };
}

function hubspotHeaders(body: string, url: string, signedUrl = url) {
  const timestamp = String(Date.now());
  const signature = createHmac("sha256", SECRET)
    .update(`POST${signedUrl}${body}${timestamp}`)
    .digest("base64");
  return {
    "x-hubspot-signature-v3": signature,
    "x-hubspot-request-timestamp": timestamp,
  };
}

function discordKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const hex = publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("hex");
  const signed = (timestamp: string, body: string) => ({
    "x-signature-ed25519": sign(null, Buffer.from(timestamp + body), privateKey).toString("hex"),
    "x-signature-timestamp": timestamp,
  });
  return { hex, signed };
}

describe("S1: Twilio repeated form keys", () => {
  const url = "https://example.com/sms";
  const legitimate = "From=%2B15551234567&Body=hello&MessageStatus=received";
  const signature = createHmac("sha1", SECRET)
    .update(`${url}BodyhelloFrom+15551234567MessageStatusreceived`)
    .digest("base64");
  const headers = {
    "x-twilio-signature": signature,
    "content-type": "application/x-www-form-urlencoded",
  };

  it("still accepts the untouched request", () => {
    expect(constructEvent("twilio", legitimate, headers, SECRET, { url }).payload).toEqual({
      From: "+15551234567",
      Body: "hello",
      MessageStatus: "received",
    });
  });

  it("rejects values appended under a valid signature", () => {
    const tampered = `${legitimate}&Body=TAMPERED&From=%2B19998887777&MessageStatus=failed`;
    expect(() => constructEvent("twilio", tampered, headers, SECRET, { url })).toThrow(
      WebhookSignatureError
    );
  });

  it("verifies genuine multi-value requests and keeps every value", () => {
    const multi = createHmac("sha1", SECRET).update(`${url}A1A2B3`).digest("base64");
    const event = constructEvent(
      "twilio",
      "A=2&A=1&B=3",
      { ...headers, "x-twilio-signature": multi },
      SECRET,
      { url }
    );
    expect(event.payload).toEqual({ A: ["2", "1"], B: "3" });
  });
});

describe("S2 and S11: option validation", () => {
  const body = '{"type":"a"}';
  const invalid = [Number.NaN, Infinity, -1, "abc"] as unknown as number[];

  it.each(invalid)("rejects tolerance %s instead of disabling replay checks", (tolerance) => {
    const old = now() - 10 * 365 * 86_400;
    expect(() =>
      constructEvent("stripe", body, stripe(body, SECRET, old), SECRET, { tolerance })
    ).toThrow(WebhookConfigurationError);
    expect(
      () => new HookGuard({ providers: { stripe: { secret: SECRET, tolerance } } })
    ).toThrow(WebhookConfigurationError);
  });

  it("allows a tolerance of zero", () => {
    expect(() =>
      constructEvent("stripe", body, stripe(body, SECRET, now() - 60), SECRET, { tolerance: 0 })
    ).toThrow(WebhookTimestampError);
  });

  it("rejects algorithms outside the allowlist", () => {
    const options = { algorithm: "md5" } as unknown as VerifyOptions;
    expect(() =>
      constructEvent("zoho", "{}", { "x-zoho-webhook-signature": "00" }, SECRET, options)
    ).toThrow(WebhookConfigurationError);
  });
});

describe("S3: Clerk secrets", () => {
  const body = '{"type":"user.deleted"}';
  const id = "msg_1";
  const signed = (key: Buffer, timestamp = now()) => ({
    "svix-id": id,
    "svix-timestamp": String(timestamp),
    "svix-signature": `v1,${createHmac("sha256", key)
      .update(`${id}.${timestamp}.${body}`)
      .digest("base64")}`,
  });

  it.each(["whsec_", "!!!!", "whsec_!!!"])("refuses malformed secret %s", (secret) => {
    expect(() => constructEvent("clerk", body, signed(Buffer.alloc(0)), secret)).toThrow(
      WebhookConfigurationError
    );
    expect(() => new HookGuard({ providers: { clerk: { secret } } })).toThrow(
      WebhookConfigurationError
    );
  });

  it("rejects wrong keys and stale timestamps", () => {
    const key = Buffer.from("real-key");
    const secret = `whsec_${key.toString("base64")}`;
    expect(constructEvent("clerk", body, signed(key), secret).id).toBe(id);
    expect(() => constructEvent("clerk", body, signed(Buffer.from("other")), secret)).toThrow(
      WebhookSignatureError
    );
    expect(() => constructEvent("clerk", body, signed(key, now() - 3600), secret)).toThrow(
      WebhookTimestampError
    );
  });
});

describe("S4: unsigned fields are declared", () => {
  it("marks header-derived fields on GitHub and Shopify", () => {
    const req = github({}, "push", { "x-github-delivery": "abc" });
    const event = constructEvent("github", req.body, req.headers, SECRET);
    expect(event.id).toBe("abc");
    expect(event.unsignedFields).toEqual(["type", "id"]);

    const body = "{}";
    const hmac = createHmac("sha256", SECRET).update(body).digest("base64");
    const shopify = constructEvent(
      "shopify",
      body,
      { "x-shopify-hmac-sha256": hmac, "x-shopify-topic": "orders/paid" },
      SECRET
    );
    expect(shopify.unsignedFields).toEqual(["type", "id"]);
  });

  it("reports nothing for a provider that signs them", () => {
    const body = '{"id":"evt_1","type":"a"}';
    const event = constructEvent("stripe", body, stripe(body), SECRET);
    expect(event.id).toBe("evt_1");
    expect(event.unsignedFields).toEqual([]);
  });
});

describe("S5: idempotency", () => {
  function memoryStore(): IdempotencyStore & { keys: Set<string> } {
    const keys = new Set<string>();
    return {
      keys,
      claim(key) {
        if (keys.has(key)) {
          return false;
        }
        keys.add(key);
        return true;
      },
      release(key) {
        keys.delete(key);
      },
    };
  }

  it("runs handlers once for a repeated delivery and still acknowledges it", async () => {
    const guard = githubGuard({ idempotency: memoryStore() });
    const handler = vi.fn();
    guard.on("push", handler);

    await deliver(guard, "github", github({}));
    const { res } = await deliver(guard, "github", github({}));

    expect(handler).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
  });

  it("is not fooled by changing an unsigned delivery ID", async () => {
    const guard = githubGuard({ idempotency: memoryStore() });
    const handler = vi.fn();
    guard.on("push", handler);

    await deliver(guard, "github", github({}, "push", { "x-github-delivery": "one" }));
    await deliver(guard, "github", github({}, "push", { "x-github-delivery": "two" }));

    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("releases the key when a handler fails, so the retry runs", async () => {
    const guard = githubGuard({ idempotency: memoryStore(), onError: () => {} });
    const handler = vi.fn().mockRejectedValueOnce(new Error("db down"));
    guard.on("push", handler);

    const first = await deliver(guard, "github", github({}));
    const retry = await deliver(guard, "github", github({}));

    expect(first.res.statusCode).toBe(500);
    expect(retry.res.statusCode).toBe(200);
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it("returns 500 without running handlers when the store fails", async () => {
    const guard = githubGuard({
      onError: () => {},
      idempotency: {
        claim() {
          throw new Error("redis down");
        },
      },
    });
    const handler = vi.fn();
    guard.on("push", handler);

    const { res } = await deliver(guard, "github", github({}));

    expect(res.statusCode).toBe(500);
    expect(handler).not.toHaveBeenCalled();
  });
});

describe("S6: handlers are scoped to a provider", () => {
  const twoProviders = () =>
    new HookGuard({
      providers: { github: { secret: SECRET }, stripe: { secret: SECRET } },
    });

  it("does not run one provider's handler for another's event", async () => {
    const guard = twoProviders();
    const handler = vi.fn();
    guard.on("stripe", "push", handler);

    await deliver(guard, "github", github({}));
    expect(handler).not.toHaveBeenCalled();

    const body = '{"type":"push"}';
    await deliver(guard, "stripe", { body: Buffer.from(body), headers: stripe(body) });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("requires a provider name when several are configured", () => {
    expect(() => twoProviders().on("push", vi.fn())).toThrow(WebhookConfigurationError);
  });

  it("refuses providers that are not configured", () => {
    expect(() => githubGuard().on("stripe", "push", vi.fn())).toThrow(WebhookConfigurationError);
    expect(() => githubGuard().middleware("stripe")).toThrow(WebhookConfigurationError);
  });
});

describe("S7: middleware failure responses", () => {
  it("returns a generic 401 and reports the detail to onError", async () => {
    const onError = vi.fn();
    const req = github({});
    req.headers["x-hub-signature-256"] = `sha256=${"00".repeat(32)}`;

    const { res } = await deliver(githubGuard({ onError }), "github", req);

    expect(res.statusCode).toBe(401);
    expect(res.body).toEqual({ error: "Invalid webhook" });
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookSignatureError);
  });

  it("returns 400 for a verified but unparseable body", async () => {
    const body = "not json";
    const digest = createHmac("sha256", SECRET).update(body).digest("hex");
    const { res } = await deliver(githubGuard({ onError: () => {} }), "github", {
      body: Buffer.from(body),
      headers: { "x-hub-signature-256": `sha256=${digest}` },
    });
    expect(res.statusCode).toBe(400);
  });

  it("returns a generic 500 for configuration problems", async () => {
    const onError = vi.fn();
    const { res } = await deliver(githubGuard({ onError }), "github", {
      body: { parsed: true },
      headers: github({}).headers,
    });
    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ error: "Webhook processing failed" });
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookConfigurationError);
  });

  it("does not log unauthenticated failures by default", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    await deliver(githubGuard(), "github", { body: Buffer.from("{}"), headers: {} });
    expect(log).not.toHaveBeenCalled();
  });
});

describe("S8 and C6: Twilio URL handling", () => {
  const url = "https://example.com/t";
  const body = '{"EventType":"x"}';
  const hash = createHash("sha256").update(body).digest("hex");
  const fullUrl = `${url}?bodySHA256=${hash}`;
  const headers = {
    "content-type": "application/json",
    "x-twilio-signature": createHmac("sha1", SECRET).update(fullUrl).digest("base64"),
  };
  const guard = () => new HookGuard({ providers: { twilio: { secret: SECRET, url } } });

  it("requires a configured URL rather than trusting the Host header", () => {
    expect(() => new HookGuard({ providers: { twilio: { secret: SECRET } } })).toThrow(
      WebhookConfigurationError
    );
    expect(() => new HookGuard({ providers: { hubspot: { secret: SECRET } } })).toThrow(
      WebhookConfigurationError
    );
  });

  it("combines the configured URL with the request's query string", async () => {
    const { res } = await deliver(guard(), "twilio", {
      body: Buffer.from(body),
      headers,
      url: `/internal/path?bodySHA256=${hash}`,
    });
    expect(res.statusCode).toBe(200);
  });

  it("ignores a client-supplied absolute URL", async () => {
    const signedForOther = createHmac("sha1", SECRET)
      .update(`https://other.example/t?bodySHA256=${hash}`)
      .digest("base64");
    const { res } = await deliver(guard(), "twilio", {
      body: Buffer.from(body),
      headers: { ...headers, "x-twilio-signature": signedForOther },
      url: `https://other.example/t?bodySHA256=${hash}`,
    });
    expect(res.statusCode).toBe(401);
  });

  it.each([
    ["https://example.com:443/sms", "https://example.com/sms"],
    ["https://example.com/sms", "https://example.com:443/sms"],
  ])("accepts a signature for %s at %s", (signedUrl, configuredUrl) => {
    const signature = createHmac("sha1", SECRET).update(`${signedUrl}Ab`).digest("base64");
    const event = constructEvent(
      "twilio",
      "A=b",
      { "x-twilio-signature": signature },
      SECRET,
      { url: configuredUrl }
    );
    expect(event.verified).toBe(true);
  });
});

describe("S9, S10, S12: stricter verification", () => {
  it("rejects a non-numeric Discord timestamp", () => {
    const { hex, signed } = discordKeys();
    expect(() =>
      constructEvent("discord", "{}", signed("not-a-number", "{}"), hex)
    ).toThrow(WebhookSignatureError);
  });

  it("rejects a stale Discord timestamp", () => {
    const { hex, signed } = discordKeys();
    expect(() =>
      constructEvent("discord", "{}", signed(String(now() - 3600), "{}"), hex)
    ).toThrow(WebhookTimestampError);
  });

  it("reports a bad Discord public key as configuration", () => {
    const { signed } = discordKeys();
    expect(() =>
      constructEvent("discord", "{}", signed(String(now()), "{}"), "not-hex")
    ).toThrow(WebhookConfigurationError);
  });

  it("does not fall back to SHA-1 past a bad SHA-256 signature", () => {
    const sha1 = createHmac("sha1", SECRET).update("{}").digest("hex");
    expect(() =>
      constructEvent(
        "github",
        "{}",
        {
          "x-hub-signature-256": `sha256=${"00".repeat(32)}`,
          "x-hub-signature": `sha1=${sha1}`,
        },
        SECRET,
        { allowLegacySha1: true }
      )
    ).toThrow(WebhookSignatureError);
  });

  it.each(["constructor", "__proto__", "toString"])("treats %s as unsupported", (provider) => {
    expect(() => constructEvent(provider as ProviderName, "{}", {}, SECRET)).toThrow(
      UnsupportedProviderError
    );
    expect(
      () => new HookGuard({ providers: { [provider]: { secret: SECRET } } })
    ).toThrow(UnsupportedProviderError);
  });
});

describe("C1: HubSpot batches", () => {
  const url = "https://example.com/hubspot";
  const items = [
    { subscriptionType: "contact.creation", objectId: 1, eventId: 100 },
    { subscriptionType: "deal.creation", objectId: 2, eventId: 101 },
  ];
  const body = JSON.stringify(items);

  it("accepts a signed array and exposes each event", () => {
    const event = constructEvent("hubspot", body, hubspotHeaders(body, url), SECRET, { url });
    expect(event.type).toBe("batch");
    expect(event.payload).toEqual({ events: items });
    expect(event.batch?.map((item) => [item.type, item.id])).toEqual([
      ["contact.creation", "100"],
      ["deal.creation", "101"],
    ]);
  });

  it("uses the shared type when every item has the same one", () => {
    const same = JSON.stringify([items[0], items[0]]);
    const event = constructEvent("hubspot", same, hubspotHeaders(same, url), SECRET, { url });
    expect(event.type).toBe("contact.creation");
  });

  it("verifies through verifyWebhook", () => {
    expect(verifyWebhook("hubspot", body, hubspotHeaders(body, url), SECRET, { url })).toBe(true);
  });

  it("dispatches each item to its handler", async () => {
    const guard = new HookGuard({ providers: { hubspot: { secret: SECRET, url } } });
    const seen: unknown[] = [];
    guard.on("contact.*", (event) => {
      seen.push(event.payload.objectId);
    });
    guard.on("deal.*", (event) => {
      seen.push(event.payload.objectId);
    });

    const { res } = await deliver(guard, "hubspot", {
      body: Buffer.from(body),
      headers: hubspotHeaders(body, url),
      method: "POST",
    });

    expect(res.statusCode).toBe(200);
    expect(seen).toEqual([1, 2]);
  });

  it("rejects non-object items", () => {
    const bad = "[1,2]";
    expect(() =>
      constructEvent("hubspot", bad, hubspotHeaders(bad, url), SECRET, { url })
    ).toThrow(WebhookPayloadError);
  });
});

describe("C2: Slack and Discord handshakes", () => {
  it("answers the Slack URL challenge without running handlers", async () => {
    const guard = new HookGuard({ providers: { slack: { secret: SECRET } } });
    const handler = vi.fn();
    guard.on("*", handler);

    const { res } = await deliver(
      guard,
      "slack",
      slack('{"type":"url_verification","challenge":"abc123"}', "application/json")
    );

    expect(res.body).toEqual({ challenge: "abc123" });
    expect(handler).not.toHaveBeenCalled();
  });

  it("answers Discord PING with PONG", async () => {
    const { hex, signed } = discordKeys();
    const guard = new HookGuard({ providers: { discord: { secret: hex } } });
    const body = '{"type":1}';

    const { res } = await deliver(guard, "discord", {
      body: Buffer.from(body),
      headers: signed(String(now()), body),
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ type: 1 });
  });

  it("lets a handler supply the Discord interaction response", async () => {
    const { hex, signed } = discordKeys();
    const guard = new HookGuard({ providers: { discord: { secret: hex } } });
    guard.on("2", () => ({ body: { type: 4, data: { content: "hi" } } }));
    const body = '{"type":2,"id":"i1"}';

    const { res } = await deliver(guard, "discord", {
      body: Buffer.from(body),
      headers: signed(String(now()), body),
    });

    expect(res.body).toEqual({ type: 4, data: { content: "hi" } });
  });

  it("parses Slack slash commands", () => {
    const req = slack(
      "command=%2Fdeploy&text=prod&trigger_id=t1",
      "application/x-www-form-urlencoded"
    );
    const event = constructEvent("slack", req.body, req.headers, SECRET);
    expect(event.type).toBe("slash_command");
    expect(event.id).toBe("t1");
    expect(event.payload).toMatchObject({ command: "/deploy", text: "prod" });
  });

  it("parses Slack interactive payloads", () => {
    const payload = encodeURIComponent('{"type":"block_actions","trigger_id":"t2"}');
    const req = slack(`payload=${payload}`, "application/x-www-form-urlencoded");
    const event = constructEvent("slack", req.body, req.headers, SECRET);
    expect(event.type).toBe("block_actions");
    expect(event.id).toBe("t2");
  });
});

describe("C3: GitHub form-encoded deliveries", () => {
  const sign256 = (body: string) =>
    `sha256=${createHmac("sha256", SECRET).update(body).digest("hex")}`;
  const contentType = "application/x-www-form-urlencoded";

  it("unwraps the payload field", () => {
    const body = `payload=${encodeURIComponent('{"action":"opened"}')}`;
    const event = constructEvent(
      "github",
      body,
      {
        "x-hub-signature-256": sign256(body),
        "x-github-event": "issues",
        "content-type": contentType,
      },
      SECRET
    );
    expect(event.type).toBe("issues.opened");
    expect(event.payload).toEqual({ action: "opened" });
  });

  it("rejects a form body with no payload field", () => {
    const body = "other=1";
    expect(() =>
      constructEvent(
        "github",
        body,
        { "x-hub-signature-256": sign256(body), "content-type": contentType },
        SECRET
      )
    ).toThrow(WebhookPayloadError);
  });
});

describe("C4: Zoho signing string", () => {
  it("matches the example in Zoho Billing's documentation", () => {
    const body = '{"created_date":"2019-03-06","event_id":"5675"}';
    const signature = createHmac("sha256", SECRET)
      .update(`namebasicsubscription_id90343${body}`)
      .digest("hex");

    const event = constructEvent(
      "zoho",
      body,
      { "x-zoho-webhook-signature": signature, "content-type": "application/json" },
      SECRET,
      { url: "https://example.com/z?subscription_id=90343&name=basic" }
    );

    expect(event.id).toBe("5675");
  });

  it("sorts and decodes form pairs together with query pairs", () => {
    const signature = createHmac("sha256", SECRET)
      .update("alpha1betatwo gamma3")
      .digest("hex");

    const event = constructEvent(
      "zoho",
      "gamma=3&alpha=1",
      {
        "x-zoho-webhook-signature": signature,
        "content-type": "application/x-www-form-urlencoded",
      },
      SECRET,
      { url: "https://example.com/z?beta=two+" }
    );

    expect(event.payload).toEqual({ gamma: "3", alpha: "1" });
  });
});

describe("C5: HubSpot URI decoding", () => {
  it("decodes the documented characters before verifying", () => {
    const url = "https://example.com/hook?redirect=https%3A%2F%2Fa.example%2Fb&tag=a%20b";
    const signedUrl = "https://example.com/hook?redirect=https://a.example/b&tag=a%20b";
    const body = "[]";
    expect(
      verifyWebhook("hubspot", body, hubspotHeaders(body, url, signedUrl), SECRET, { url })
    ).toBe(true);
  });
});

describe("C7: Twilio default response", () => {
  it("acknowledges with empty TwiML rather than JSON", async () => {
    const url = "https://example.com/sms";
    const signature = createHmac("sha1", SECRET).update(`${url}Ab`).digest("base64");
    const guard = new HookGuard({ providers: { twilio: { secret: SECRET, url } } });

    const { res } = await deliver(guard, "twilio", {
      body: Buffer.from("A=b"),
      headers: { "x-twilio-signature": signature },
    });

    expect(res.headers["Content-Type"]).toBe("text/xml");
    expect(res.body).toBe("<Response/>");
  });
});

describe("C8: verifyWebhook", () => {
  const signature = `sha256=${createHmac("sha256", SECRET).update("not json").digest("hex")}`;
  const headers = { "x-hub-signature-256": signature };

  it("checks authenticity without parsing", () => {
    expect(verifyWebhook("github", "not json", headers, SECRET)).toBe(true);
  });

  it("accepts a request object", () => {
    expect(verifyWebhook("github", { body: "not json", headers }, SECRET)).toBe(true);
    expect(verifyWebhook("github", { body: "other", headers }, SECRET)).toBe(false);
  });

  it("throws for an unknown provider instead of returning false", () => {
    expect(() => verifyWebhook("nope" as ProviderName, "{}", {}, SECRET)).toThrow(
      UnsupportedProviderError
    );
  });
});

describe("R1: acknowledgement", () => {
  it("responds only after handlers finish", async () => {
    const order: string[] = [];
    const guard = githubGuard();
    guard.on("push", async () => {
      order.push("handler");
    });
    const res = {
      status(code: number) {
        order.push(`status ${code}`);
        return { json() {} };
      },
    };

    await guard.middleware("github")(github({}), res, vi.fn());

    expect(order).toEqual(["handler", "status 200"]);
  });

  it("returns 500 when a handler fails, so the provider retries", async () => {
    const guard = githubGuard({ onError: () => {} });
    guard.on("push", () => {
      throw new WebhookPayloadError("rejected by application code");
    });

    const { res } = await deliver(guard, "github", github({}));

    expect(res.statusCode).toBe(500);
  });

  it("supports acknowledging first", async () => {
    const order: string[] = [];
    const guard = githubGuard();
    guard.on("push", () => {
      order.push("handler");
    });
    const res = {
      status(code: number) {
        order.push(`status ${code}`);
        return { json() {} };
      },
    };

    await guard.middleware("github", { ack: "immediate" })(github({}), res, vi.fn());

    expect(order).toEqual(["status 200", "handler"]);
  });

  it("refuses immediate acknowledgement combined with callNext", () => {
    expect(() =>
      githubGuard().middleware("github", { ack: "immediate", callNext: true })
    ).toThrow(WebhookConfigurationError);
  });

  it("logs handler failures when no onError is set", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const guard = githubGuard();
    guard.on("push", () => {
      throw new Error("db down");
    });

    await deliver(guard, "github", github({}));

    expect(log).toHaveBeenCalledOnce();
  });
});

describe("R2: a failing onError", () => {
  it.each([
    ["throws", () => { throw new Error("logger broke"); }],
    ["rejects", async () => { throw new Error("logger broke"); }],
  ])("is contained when it %s", async (_, onError) => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const later = vi.fn();
    const guard = githubGuard({ onError });
    guard.on("push", () => {
      throw new Error("db down");
    });
    guard.on("push", later);

    const { res } = await deliver(guard, "github", github({}));
    await new Promise((resolve) => setImmediate(resolve));

    expect(res.statusCode).toBe(500);
    expect(later).toHaveBeenCalledOnce();
    expect(log).toHaveBeenCalledOnce();
  });
});

describe("R3: handler timeouts", () => {
  it("fails a hung handler and continues with the next one", async () => {
    const onError = vi.fn();
    const later = vi.fn();
    const guard = githubGuard({ handlerTimeoutMs: 10, onError });
    guard.on("push", () => new Promise<void>(() => {}));
    guard.on("push", later);

    const { res } = await deliver(guard, "github", github({}));

    expect(res.statusCode).toBe(500);
    expect(later).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0]?.[0]).toBeInstanceOf(WebhookHandlerTimeoutError);
  });

  it.each([0, -5, Number.NaN])("rejects handlerTimeoutMs %s", (handlerTimeoutMs) => {
    expect(() => githubGuard({ handlerTimeoutMs })).toThrow(WebhookConfigurationError);
  });
});

describe("D1: Fetch inputs", () => {
  it("reads a Headers object", () => {
    const req = github({});
    const event = constructEvent("github", req.body, new Headers(req.headers), SECRET);
    expect(event.type).toBe("push");
  });

  it("accepts Uint8Array and ArrayBuffer bodies", () => {
    const { headers } = github({});
    const bytes = new TextEncoder().encode("{}");
    expect(constructEvent("github", bytes, headers, SECRET).verified).toBe(true);
    expect(
      constructEvent("github", bytes.buffer as ArrayBuffer, headers, SECRET).verified
    ).toBe(true);
  });
});

describe("D2 and D3: clear configuration errors", () => {
  const { headers } = github({});

  it("refuses a parsed body, even one that would re-serialize identically", async () => {
    const onError = vi.fn();
    const { res } = await deliver(githubGuard({ onError }), "github", { body: {}, headers });
    expect(res.statusCode).toBe(500);
    expect(onError.mock.calls[0]?.[0].message).toContain("raw");
  });

  it("refuses a missing body", async () => {
    const { res } = await deliver(githubGuard({ onError: () => {} }), "github", {
      body: undefined,
      headers,
    });
    expect(res.statusCode).toBe(500);
  });

  it("raises WebhookConfigurationError for bad arguments", () => {
    const missing = undefined as unknown as string;
    const body = { a: 1 } as unknown as string;
    expect(() => constructEvent("github", "{}", headers, missing)).toThrow(
      WebhookConfigurationError
    );
    expect(() => constructEvent("github", body, headers, SECRET)).toThrow(
      WebhookConfigurationError
    );
  });
});

describe("D5: API behavior", () => {
  it("validates configuration at startup", () => {
    const empty = undefined as unknown as ConstructorParameters<typeof HookGuard>[0];
    expect(() => new HookGuard(empty)).toThrow(WebhookConfigurationError);
    expect(() => new HookGuard({ providers: { stripe: { secret: "" } } })).toThrow(
      WebhookConfigurationError
    );
    expect(
      () => new HookGuard({ providers: { stripe: { secret: SECRET, url: "not a url" } } })
    ).toThrow(WebhookConfigurationError);
  });

  it("supports a catch-all handler", async () => {
    const guard = githubGuard();
    const handler = vi.fn();
    guard.on("*", handler);
    await deliver(guard, "github", github({}));
    expect(handler).toHaveBeenCalledOnce();
  });

  it("hands the event to the next middleware without responding", async () => {
    const guard = githubGuard();
    const req: HttpRequestLike = github({});
    const res = fakeRes();
    const next = vi.fn();

    await guard.middleware("github", { callNext: true })(req, res, next);

    expect(req.webhookEvent?.type).toBe("push");
    expect(res.statusCode).toBe(0);
    expect(next).toHaveBeenCalledWith(undefined);
  });

  it("passes handler failures to next when using callNext", async () => {
    const failure = new Error("db down");
    const guard = githubGuard({ onError: () => {} });
    guard.on("push", () => {
      throw failure;
    });

    const { next } = await deliver(guard, "github", github({}), { callNext: true });

    expect(next).toHaveBeenCalledWith(failure);
  });
});

describe("secret rotation", () => {
  const body = '{"type":"a"}';

  it("accepts a signature from any listed secret", () => {
    const secrets = ["new-secret", "old-secret"];
    expect(constructEvent("stripe", body, stripe(body, "old-secret"), secrets).verified).toBe(true);
    expect(constructEvent("stripe", body, stripe(body, "new-secret"), secrets).verified).toBe(true);
  });

  it("rejects a signature from an unlisted secret", () => {
    expect(() =>
      constructEvent("stripe", body, stripe(body, "other"), ["new-secret", "old-secret"])
    ).toThrow(WebhookSignatureError);
  });

  it("refuses an empty list or an empty entry", () => {
    expect(() => constructEvent("stripe", body, stripe(body), [])).toThrow(
      WebhookConfigurationError
    );
    expect(() => constructEvent("stripe", body, stripe(body), [SECRET, ""])).toThrow(
      WebhookConfigurationError
    );
  });

  it("reports timestamp and header failures rather than trying other secrets", () => {
    expect(() => constructEvent("stripe", body, {}, ["a", "b"])).toThrow(MissingHeaderError);
  });
});
