# Changelog

This project follows [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may include breaking changes.

## 0.1.0 (unreleased)

First public release.

### Providers

Signature verification for Stripe, GitHub, Shopify, Slack, Twilio, Zoho Billing, Zoho Sign, HubSpot, Clerk, and Discord.

### Features

- `constructEvent`, `buildWebhookEvent`, and `verifyWebhook`
- `HookGuard` class with Express-compatible middleware
- Automatic Slack URL verification and Discord PING handling
- Handlers can return the HTTP response
- Handlers scoped by provider, with prefix and catch-all patterns
- Optional idempotency store for duplicate deliveries
- `handlerTimeoutMs` for hung handlers
- Secret rotation with `secret: [newSecret, oldSecret]`
- HubSpot batch support
- Fetch `Headers`, `Uint8Array`, and `ArrayBuffer` inputs
- ESM and CommonJS builds with TypeScript types
