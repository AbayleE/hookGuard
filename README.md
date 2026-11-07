# HookGuard

Zero-dependency webhook signature verification for Node.js. Pass in the raw request and get back a trusted event, or a typed error if the signature, timestamp, or payload is not authentic.

Supported providers: **Stripe**, **GitHub**, **Shopify**, **Slack**, **Twilio**, **Zoho Billing**, **Zoho Sign**, **HubSpot**, **Clerk**, and **Discord**.

> **Status: 0.x.** The API may change before 1.0. Provider support is tested against locally generated signatures, not yet against live deliveries. Please [open an issue](https://github.com/AbayleE/hookGuard/issues) if a real webhook fails to verify.

## Why this exists

Webhooks are inbound HTTP callbacks. Anyone who can reach your URL can POST a fake `payment_intent.succeeded` unless you verify the provider's signature. HookGuard does that with `crypto.timingSafeEqual`, enforces replay windows where the provider signs a timestamp, and parses the event only after the request is trusted.

**Scope:** HookGuard handles webhooks you *receive*. It does not send webhooks, so it has no outbound retries, backoff, or circuit breakers. The provider retries failed deliveries, and HookGuard's job is to report failures honestly so those retries happen.

## Install

```bash
npm install @efrata/hookguard
```

Requires Node.js 20 or later. Works with both `import` and `require`. No runtime dependencies.

## Quick start

Signatures cover the exact bytes received, so you must pass the **raw body**. A JSON body parser will break verification.

```ts
import express from "express";
import { HookGuard } from "@efrata/hookguard";

const guard = new HookGuard({
  providers: {
    stripe: { secret: process.env.STRIPE_WEBHOOK_SECRET! },
  },
  onError: (err, event) => console.error(err.message, event?.type),
});

guard.on("payment_intent.succeeded", async (event) => {
  await fulfillOrder(event.payload);
});

const app = express();

// Register this before any express.json() that would also match these routes.
app.post(
  "/webhooks/stripe",
  express.raw({ type: "*/*" }),
  guard.middleware("stripe")
);
```

Use `type: "*/*"`. With a narrower type, a request sent with a different `Content-Type` arrives without a raw body and gets a 500 instead of a 401.

### Without the middleware

`constructEvent` works in any framework. It accepts a `Buffer`, string, `Uint8Array`, or `ArrayBuffer` body, and a plain headers object or a Fetch `Headers`.

```ts
import { constructEvent, HookGuardError } from "@efrata/hookguard";

// For example, a Next.js route handler
export async function POST(request: Request) {
  const body = await request.arrayBuffer();

  try {
    const event = constructEvent(
      "stripe",
      body,
      request.headers,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
    await handle(event);
    return new Response(null, { status: 200 });
  } catch (error) {
    if (error instanceof HookGuardError && error.code !== "INVALID_CONFIGURATION") {
      return new Response("Invalid webhook", { status: 401 });
    }
    throw error;
  }
}
```

`buildWebhookEvent` is an alias of `constructEvent`. Both also accept a request object:

```ts
const event = constructEvent("github", { body: rawBody, headers }, secret);
```

To type the payload, pass a type argument. This is not validated at runtime.

```ts
const event = constructEvent<{ id: string }>("stripe", body, headers, secret);
```

`verifyWebhook(...)` takes the same arguments and returns a boolean. It checks authenticity only and does not parse the body. Configuration mistakes still throw, so a broken setup cannot look like a forged request.

## Providers

| Provider | Header(s) | Algorithm | Signed content | Replay window |
| --- | --- | --- | --- | --- |
| Stripe | `stripe-signature` (`t`, `v1`) | HMAC-SHA256 | `${timestamp}.${rawBody}` | Yes |
| GitHub | `x-hub-signature-256` | HMAC-SHA256 | raw body (`sha256=` prefix) | No |
| Shopify | `x-shopify-hmac-sha256` | HMAC-SHA256 | raw body (Base64) | No |
| Slack | `x-slack-signature`, `x-slack-request-timestamp` | HMAC-SHA256 | `v0:${timestamp}:${rawBody}` | Yes |
| Twilio | `x-twilio-signature` | HMAC-SHA1 | URL + sorted form fields; for JSON, URL with `bodySHA256` | No |
| Zoho Billing | `x-zoho-webhook-signature` | HMAC-SHA256 by default | sorted query and form pairs + raw JSON | No |
| Zoho Sign | `x-zs-webhook-signature` | HMAC-SHA256 (Base64) | raw body | No |
| HubSpot | `x-hubspot-signature-v3`, `x-hubspot-request-timestamp` | HMAC-SHA256 | method + URI + body + timestamp | Yes |
| Clerk | `svix-id`, `svix-timestamp`, `svix-signature` | HMAC-SHA256 | `${id}.${timestamp}.${rawBody}` | Yes |
| Discord | `x-signature-ed25519`, `x-signature-timestamp` | Ed25519 | `timestamp + rawBody` (public key as the "secret") | Yes |

The default replay window is **5 minutes**, in both directions. Change it with `{ tolerance: seconds }`. Invalid values throw rather than disabling the check.

### Provider notes

**Twilio and HubSpot** sign the URL, so they need the public address the provider called. Set it explicitly, especially behind a proxy. HookGuard does not derive it from the `Host` header, which a client controls. With the middleware, the incoming query string is appended automatically.

```ts
new HookGuard({
  providers: {
    twilio: { secret: authToken, url: "https://example.com/webhooks/twilio" },
    hubspot: { secret: clientSecret, url: "https://example.com/webhooks/hubspot" },
  },
});

// With constructEvent, pass the full URL, including any query string
constructEvent("hubspot", body, headers, clientSecret, {
  method: "POST",
  url: "https://example.com/webhooks/hubspot",
});
```

**Twilio** form webhooks need the raw body too, which `express.raw({ type: "*/*" })` provides. The middleware answers with empty TwiML. Return a response from a handler to reply with your own. Repeated form fields appear as arrays in `event.payload`.

**HubSpot** sends batches. The event has `payload.events`, plus `batch` with one event per item. Its `type` is the shared `subscriptionType`, or `"batch"` if they differ. The middleware runs your handlers once per item.

**Slack:** the middleware answers the `url_verification` challenge. Slash commands arrive as `slash_command`, and interactive payloads use their own `type`, such as `block_actions`.

**Discord:** the middleware answers PING. Return your interaction response from a handler:

```ts
guard.on("2", () => ({ body: { type: 4, data: { content: "Hello" } } }));
```

**GitHub:** both `application/json` and form-encoded deliveries work. The legacy SHA-1 header is refused unless you set `allowLegacySha1: true`.

**Zoho:** if your webhook uses query parameters, set `url` so they can be included in the signature. The optional `algorithm` setting is not described in Zoho's documentation. Zoho Books has not been confirmed to use the same scheme as Zoho Billing.

## Middleware behavior

`guard.middleware(provider, options)` works with Express and compatible frameworks.

| Situation | Response |
| --- | --- |
| Verified, handlers succeed | 200, or what a handler returned |
| Verified, a handler fails | 500, so the provider retries |
| Bad signature, timestamp, or missing header | 401 |
| Verified, but the body cannot be parsed | 400 |
| Configuration error | 500 |

Response bodies are generic, because callers are unauthenticated. Details go to `onError`, which receives every failure. Without `onError`, everything except rejected requests goes to `console.error`.

### Slow handlers

By default the response waits for your handlers, so a failure can be retried. Providers have short deadlines (Slack allows about 3 seconds), so for slow work either hand off to a queue from your handler, or respond first:

```ts
guard.middleware("slack", { ack: "immediate" });
```

With `ack: "immediate"`, the provider sees success before handlers run, so **a failed handler is not retried**. Use it only with a durable hand-off.

Set `handlerTimeoutMs` to fail handlers that hang. HookGuard stops waiting, but cannot cancel the handler.

### Registering handlers

```ts
guard.on("push", handler);                    // only one provider configured
guard.on("stripe", "charge.failed", handler); // required with several providers
guard.on("stripe", "customer.*", handler);    // prefix wildcard
guard.on("stripe", "*", handler);             // every event
```

`customer.*` matches `customer.created`, but not `customer` on its own.

Handlers run one at a time, in the order they were registered.

### Handling the response yourself

With `callNext`, HookGuard verifies the request, runs handlers, sets `req.webhookEvent`, and calls `next()`. Failures after verification go to `next(err)`. Failed verification is still rejected directly.

```ts
import type { HttpRequestLike } from "@efrata/hookguard";

app.post(
  "/webhooks/github",
  express.raw({ type: "*/*" }),
  guard.middleware("github", { callNext: true }),
  (req, res) => {
    const { webhookEvent } = req as HttpRequestLike;
    res.json({ type: webhookEvent?.type });
  }
);
```

## Security best practices

- **Keep the raw body.** Do not parse it before verification.
- **Use HTTPS** for every webhook endpoint.
- **Fail at startup if a secret is missing.** `new HookGuard()` throws on empty or malformed secrets, so create it when your app boots.
- **Rotate secrets without downtime.** Accept both during the switch: `secret: [newSecret, oldSecret]`.
- **Limit body size** at the framework level. `express.raw()` defaults to 100 KB, so raise it with `limit` if your provider sends more.
- **Handle replays.** See below.
- **Do not trust unsigned fields.** See below.

### Replays

A valid request can be captured and sent again. A timestamp only limits how long that works, and five providers do not sign one: GitHub, Shopify, Twilio, Zoho, and Zoho Sign accept a captured request indefinitely. Providers also retry legitimately, so your handlers should be idempotent either way.

Pass an `idempotency` store to skip repeats:

```ts
const guard = new HookGuard({
  providers: { github: { secret } },
  idempotency: {
    // Must be atomic. Return true if this key is new.
    claim: async (key) => (await redis.set(key, "1", "EX", 86400, "NX")) === "OK",
    // Called after a handler fails, so the provider's retry can run.
    release: async (key) => void (await redis.del(key)),
  },
});
```

The key uses the provider's event ID when it is signed. When the ID comes from an unsigned header, the key is a hash of the body instead, because an attacker could change that header. As a result, a manual "redeliver" of the same GitHub or Shopify body is treated as a duplicate.

### Unsigned fields

`event.payload` and `event.rawBody` are always covered by the signature. Some other fields are not, and `event.unsignedFields` lists them:

| Provider | Unsigned | Source |
| --- | --- | --- |
| GitHub | `type`, `id` | `x-github-event`, `x-github-delivery` |
| Shopify | `type`, `id` | `x-shopify-topic`, `x-shopify-webhook-id` |
| Twilio | `id` | `i-twilio-idempotency-token` |

Someone holding one captured GitHub or Shopify request could resend its body under a different `type`. Before taking a sensitive action, check that the payload is what that event type should contain. `event.headers` is also unauthenticated, apart from any headers the provider's scheme signs.

## Errors

All errors extend `HookGuardError` and have a stable `code`. Prefer checking `code` over `instanceof` if your app could load both the ESM and CommonJS builds.

| Class | `code` | Meaning |
| --- | --- | --- |
| `WebhookSignatureError` | `SIGNATURE_VERIFICATION_FAILED` | Signature is wrong or malformed |
| `WebhookTimestampError` | `TIMESTAMP_OUT_OF_TOLERANCE` | Outside the replay window |
| `MissingHeaderError` | `MISSING_HEADER` | Required header absent |
| `WebhookPayloadError` | `INVALID_PAYLOAD` | Authentic, but could not be parsed |
| `WebhookConfigurationError` | `INVALID_CONFIGURATION` | Your setup needs fixing |
| `UnsupportedProviderError` | `UNSUPPORTED_PROVIDER` | Unknown provider name |
| `WebhookHandlerTimeoutError` | `HANDLER_TIMEOUT` | Handler exceeded `handlerTimeoutMs` |

## Event shape

```ts
interface WebhookEvent<TPayload> {
  provider: ProviderName;
  type: string;
  id?: string;                  // provider's event or delivery ID
  payload: TPayload;
  rawBody: string;
  headers: Record<string, string>;
  receivedAt: Date;             // when HookGuard processed it
  verified: true;
  unsignedFields: readonly ("type" | "id")[];
  batch?: readonly WebhookEvent<TPayload>[]; // HubSpot batches
}
```

## Development

```bash
npm ci
npm run typecheck
npm test
npm run build
```

To try the demo server, set `STRIPE_WEBHOOK_SECRET` and `GITHUB_WEBHOOK_SECRET`, then run `npm run example`.

Report security issues as described in [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE)
