# HookGuard

Zero-dependency webhook signature verification for Node.js. Pass the raw request to `constructEvent` (or `buildWebhookEvent`) and get back a trusted event object — or a typed error if the signature, timestamp, or payload is not authentic.

Supported providers: **Stripe**, **GitHub**, **Shopify**, **Slack**, **Twilio**, **Zoho**, **HubSpot**, **Clerk**, and **Discord**.

## Why this exists

Webhooks are inbound HTTP callbacks. Anyone who can reach your URL can POST a fake `payment_intent.succeeded` unless you verify the provider's HMAC (or Ed25519) signature against a shared secret. HookGuard does that verification with `crypto.timingSafeEqual`, enforces replay windows where the provider signs a timestamp, and parses the event only after the request is trusted.

## Install

```bash
npm install hookguard
```

Node.js 18+. No production dependencies.

## Quick start

Keep the **raw body**. JSON parsers that re-serialize the payload will break signatures.

```ts
import { constructEvent, WebhookSignatureError } from "hookguard";

export function handleStripeWebhook(req: {
  body: Buffer;
  headers: Record<string, string | string[] | undefined>;
}) {
  const event = constructEvent(
    "stripe",
    req.body,
    req.headers,
    process.env.STRIPE_WEBHOOK_SECRET!
  );

  // event.verified === true
  return event;
}
```

`buildWebhookEvent` is an alias of `constructEvent` and accepts the same arguments, including a request object:

```ts
import { buildWebhookEvent } from "hookguard";

const event = buildWebhookEvent(
  "github",
  { body: rawBody, headers },
  process.env.GITHUB_WEBHOOK_SECRET!
);
```

## Provider notes

| Provider | Header(s) | Algorithm | Signed payload |
| --- | --- | --- | --- |
| Stripe | `stripe-signature` (`t`, `v1`) | HMAC-SHA256 | `${timestamp}.${rawBody}` |
| GitHub | `x-hub-signature-256` or `x-hub-signature` | HMAC-SHA256 / HMAC-SHA1 | raw body (`sha256=` / `sha1=` prefix) |
| Shopify | `x-shopify-hmac-sha256` | HMAC-SHA256 | raw body (Base64) |
| Slack | `x-slack-signature`, `x-slack-request-timestamp` | HMAC-SHA256 | `v0:${timestamp}:${rawBody}` |
| Zoho(Books/Billing)| `x-zoho-webhook-signature` | HMAC-SHA256 by default, configurable | raw body |
| Twilio | `x-twilio-signature` | HMAC-SHA1 | URL + sorted form fields, or URL + JSON body |
| HubSpot | `x-hubspot-signature-v3`, `x-hubspot-request-timestamp` | HMAC-SHA256 | `METHOD + URI + body + timestamp` |
| Clerk | `svix-id`, `svix-timestamp`, `svix-signature` | HMAC-SHA256 | `${id}.${timestamp}.${rawBody}` |
| Discord | `x-signature-ed25519`, `x-signature-timestamp` | Ed25519 | `timestamp + rawBody` (public key as the "secret") |
| Zoho Sign | `x-zs-webhook-signature` | HMAC-SHA256 (Base64) | raw body |

Stripe, Slack, HubSpot, Clerk, and Discord reject timestamps older (or newer) than **5 minutes** by default. Override with `{ tolerance: seconds }`.

Twilio and HubSpot need the public URL the provider called:

```ts
constructEvent("twilio", body, headers, authToken, {
  url: "https://example.com/webhooks/twilio",
  contentType: "application/x-www-form-urlencoded",
});

constructEvent("hubspot", body, headers, clientSecret, {
  method: "POST",
  url: "https://example.com/webhooks/hubspot",
});
```

Zoho algorithm override:

```ts
constructEvent("zoho", body, headers, secret, { algorithm: "sha512" });
```

## Errors

All verification failures throw subclasses of `HookGuardError`:

- `WebhookSignatureError`
- `WebhookTimestampError`
- `MissingHeaderError`
- `WebhookPayloadError`
- `WebhookConfigurationError`
- `UnsupportedProviderError`

`verifyWebhook(...)` returns `boolean` instead of throwing for signature/header failures.

## Express

```ts
import { HookGuard } from "hookguard";

const guard = new HookGuard({
  providers: {
    stripe: { secret: process.env.STRIPE_WEBHOOK_SECRET! },
  },
});

guard.on("payment_intent.succeeded", async (event) => {
  console.log(event.payload);
});

app.post(
  "/webhooks/stripe",
  express.raw({ type: "application/json" }),
  guard.middleware("stripe")
);
```

## Scripts

```bash
npm test
npm run build
```
