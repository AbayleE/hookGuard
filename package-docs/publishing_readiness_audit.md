# HookGuard: Publishing Readiness Audit

| | |
| --- | --- |
| **Audit date** | 2026-11-07 |
| **Commit** | `ef10bbd` (`main`, clean tree) |
| **Package** | `hookguard@1.0.0` |
| **Environment** | Node 22.14.0, npm 10.9.2, Windows 11 |
| **Changes made** | This report only. No source edits, nothing published, `dist/` untouched. |

## Remediation status

Fixes were applied after this audit. The findings below describe the code at `ef10bbd` and are kept as the original record.

| Area | Status |
| --- | --- |
| P1 package name | **Open.** Renamed to `@efrata/hookguard` as a placeholder; scope ownership is unconfirmed |
| P2–P5 packaging | Fixed |
| S1–S3, S5–S12 security | Fixed |
| S4 unsigned fields | Mitigated: declared in `event.unsignedFields` and documented; the provider's scheme cannot be changed |
| C1–C3, C5–C8 providers | Fixed. C5's `%3F` handling still needs a real request |
| C4 Zoho | Implemented from Zoho Billing's docs. Output encoding is unconfirmed; Zoho Books claim removed from the README |
| R1–R3 reliability | Fixed |
| D1–D5 developer experience | Fixed, with the exceptions below |
| Zoho Sign | **Open.** Vendor specification unconfirmed |
| Live provider testing (Phase 4) | **Open.** Nothing has been tested against a real delivery |

**Deliberately unchanged:** `buildWebhookEvent` stays as an alias. The middleware still targets Express-compatible responses, so Fastify users should call `constructEvent` directly. No linter was added, and `CONTRIBUTING.md` was skipped.

**Breaking changes from the audited code:** the middleware waits for handlers by default; Twilio and HubSpot need a configured `url`; the GitHub SHA-1 fallback is opt-in; `on()` needs a provider name when several are configured; `event.timestamp` became `event.receivedAt`.

**Tooling note:** `vitest@4` crashes dependency resolution on npm 10.9.2, so `package-lock.json` was generated with npm 11. `npm ci` and `npm install` both work on npm 10 with this lockfile. If you add or upgrade dev dependencies and see `Cannot read properties of null (reading 'edgesOut')`, run the command with `npx npm@11`.

---

## 1. Verdict

**Not ready to publish.** The package cannot be published under its current name, and it would ship a stranger's package as a runtime dependency.

The cryptographic core is good. Every HMAC provider compares digests with `crypto.timingSafeEqual`, verifies raw bytes, and parses only after verification. The problems are around that core:

1. **Packaging blockers.** The npm name belongs to someone else, a third-party package is listed as a dependency, the license file is not shipped, and `dist/` is stale.
2. **One real tamper bypass.** A captured Twilio request can be altered and still pass verification with `verified: true`.
3. **Two fail-open misconfigurations.** A `NaN` tolerance turns off replay protection, and a malformed Clerk secret lets anyone forge events.
4. **Providers that do not work in real use.** Real HubSpot batches are rejected, and the middleware cannot complete the Slack or Discord endpoint handshakes.
5. **Silent event loss.** The middleware returns 200 before handlers run, so a failed handler is never retried.

The 38 passing tests miss all of this because they cover the happy paths and basic rejections, not these cases.

### Findings by severity

| Severity | Count | IDs |
| --- | --- | --- |
| Blocker (cannot publish) | 4 | P1–P4 |
| High | 6 | S1, S2, C1, C2, R1, R2 |
| Medium | 13 | S3–S7, C3–C6, R3, D1, D2, P5 |
| Low / informational | 10 | S8–S12, C7, C8, D3–D5 |

### How findings were checked

| Label | Meaning |
| --- | --- |
| **Reproduced** | Ran a proof of concept against a fresh build of `src/` and observed the result. |
| **Code** | Established by reading the code; not executed. |
| **Vendor doc** | Compared with the provider's own documentation or SDK source. |
| **Unverified** | Could not be confirmed. Stated as such. |

No test was run against a live provider. All signatures were generated locally following each provider's scheme.

### Baseline results

| Check | Result |
| --- | --- |
| `vitest run` | 38 of 38 pass |
| `tsc --noEmit` (`src`) | Pass |
| `tsc` including `tests` and `examples` | Pass (the project's `typecheck` script excludes both) |
| `publint` | No issues |
| `attw` | Warning: `require` resolves to ESM (see P5 in section 6.3) |
| `npm audit --omit=dev` | 4 moderate, all through the `hookguard` self-dependency |
| `npm audit` (all) | 12: 3 critical, 2 high, 7 moderate |

---

## 2. Webhook security

### 2.1 Signature implementation review

| Provider | Algorithm | Constant-time compare | Raw bytes | Replay window | Assessment |
| --- | --- | --- | --- | --- | --- |
| Stripe | HMAC-SHA256 | Yes | Yes | Yes | Sound; multiple `v1` signatures supported |
| GitHub | HMAC-SHA256, SHA-1 fallback | Yes | Yes | Not signed by provider | Sound; see S4, S10 |
| Shopify | HMAC-SHA256 | Yes | Yes | Not signed by provider | Sound; see S4 |
| Slack | HMAC-SHA256 | Yes | Yes | Yes | Sound; see C2 |
| Twilio | HMAC-SHA1 (provider's scheme) | Yes | Parsed form | Not signed by provider | **Bypass: S1** |
| Zoho | HMAC, SHA-256 default | Yes | Yes | Not signed by provider | Incomplete: C4 |
| Zoho Sign | HMAC-SHA256 | Yes | Yes | Not signed by provider | Sound as coded; vendor spec unverified |
| HubSpot v3 | HMAC-SHA256 | Yes | Yes | Yes | Crypto sound; C1, C5 |
| Clerk (Svix) | HMAC-SHA256 | Yes | Yes | Yes | **Fail-open on bad secret: S3** |
| Discord | Ed25519 | N/A (`crypto.verify`) | Yes | Yes, with a gap (S9) | Sound |

**Timing attacks: pass.** All HMAC paths go through `safeEqual` (`src/utils/crypto.ts:14`), which uses `timingSafeEqual`. A search found no direct `===` comparison of signatures. On a length mismatch it returns early, which reveals only the digest length, and that is public. Comparing decoded bytes rather than strings is the right design.

**Tamper resistance: pass, except S1.** Signed content is built from `rawBody` bytes, not re-serialized JSON. The body-tamper tests fail as they should.

**Parse after verify: pass.** `constructEvent` runs `strategy.verify` before `strategy.parse` (`src/verify.ts:48-49`).

**Secrets:** nothing sensitive appears in git history. `.env` is empty, ignored, and not in the tarball.

### 2.2 Security findings

#### S1. High: Twilio form parameters can be tampered with under a valid signature

**Reproduced. Vendor doc.** `src/providers/twilio.ts:55`, `src/utils/request.ts:48`

The signed string uses `params.get(key)`, which reads only the **first** value of a repeated key. The payload parser keeps the **last** value. An attacker can append duplicates, and the signature still matches the original fields while the event carries the attacker's values.

```text
Signed, legitimate: From=+15551234567&Body=hello&MessageStatus=received
Attacker appends:   &Body=TAMPERED&From=+19998887777&MessageStatus=failed

Result: verified: true, type: "failed"
        payload: { From: "+19998887777", Body: "TAMPERED", MessageStatus: "failed" }
```

**Precondition:** one captured request (URL, body, signature). Twilio signs no timestamp, so that capture never expires.

Twilio's SDK includes every value, de-duplicated and sorted (`toFormUrlEncodedParam` in `twilio-node`), so this is a bug in this library and not a weakness of Twilio's scheme. The same line also rejects legitimate multi-value requests (reproduced).

```ts
for (const key of keys) {
  for (const value of [...new Set(params.getAll(key))].sort()) {
    signed += key + value;
  }
}
```

Also make `parseFormBody` keep repeated keys as arrays. Otherwise value order, which the signature does not cover, still decides what the application sees. Add a regression test using the payload above.

#### S2. High: an invalid `tolerance` silently disables replay protection

**Reproduced.** `src/utils/request.ts:81`

`age > tolerance` is always false when `tolerance` is `NaN`. The common pattern `Number(process.env.WEBHOOK_TOLERANCE)` produces `NaN` when the variable is unset.

| `tolerance` | Stripe event signed 10 years ago |
| --- | --- |
| Default | Rejected (correct) |
| `NaN` | **Accepted** |
| `"abc"` (from JS) | **Accepted** |
| `Infinity` | **Accepted** |

**Fix:** throw `WebhookConfigurationError` unless `Number.isFinite(tolerance) && tolerance >= 0`. If disabling the check is a feature you want, make it an explicit option.

#### S3. Medium: a malformed Clerk secret becomes an empty HMAC key, allowing forgery

**Reproduced.** `src/providers/clerk.ts:30`

Node's base64 decoder is lenient. Secrets such as `"whsec_"`, `"!!!!"` and `"whsec_!!!"` pass the non-empty check and decode to zero bytes. Anyone can then compute a valid signature with an empty key; forged events returned `verified: true` for all three.

Likelihood is low, since it needs a truncated or placeholder secret, but the impact is complete forgery and nothing indicates a problem.

**Fix:** decode strictly and throw `WebhookConfigurationError` if the result is empty or does not round-trip.

#### S4. Medium: `event.type` comes from unsigned headers but the event says `verified: true`

**Reproduced.** `src/providers/github.ts:29`, `src/providers/shopify.ts:20`

GitHub and Shopify sign only the body. `x-github-event` and `x-shopify-topic` are not signed, yet they set `event.type`, and that drives handler routing. With a captured body and signature, an attacker can resend it under a different type, for example labelling an order payload `orders.paid`. `event.headers` has the same limitation.

**Fix:** document which fields are authenticated, and consider exposing the header-derived type as separately marked data. Applications should check that payloads match the event type before taking action.

#### S5. Medium: no replay defense where the provider signs no timestamp

**Code.** GitHub, Shopify, Twilio, Zoho, Zoho Sign

The README correctly limits its replay claim to timestamped providers, but it does not warn that the other five accept a captured request indefinitely. Even on timestamped providers, replay is possible inside the 5-minute window.

**Fix:** add a normalized `event.id` (for example `x-github-delivery`, `x-shopify-webhook-id`, `svix-id`, Stripe's `id`), plus an optional `seen(id)` hook or store interface. Add a README section on idempotent handling.

#### S6. Medium: handlers are matched by event type only, across all providers

**Reproduced.** `src/hookguard.ts:29`, `:80`

With Clerk and Stripe on one guard, one `on("user.created")` handler fired for both `["clerk", "stripe"]`. Different providers' events can reach a handler written for only one payload shape.

**Fix:** scope registration, for example `guard.on("stripe", "payment_intent.succeeded", fn)` or `guard.provider("stripe").on(...)`.

#### S7. Medium: middleware exposes configuration errors to unauthenticated callers

**Reproduced.** `src/hookguard.ts:64-67`

Every failure returns 401 with `error.message`:

```json
401 { "error": "Webhook secret must be a non-empty string (is your env var set?)" }
401 { "error": "Twilio verification requires the full webhook URL (options.url)" }
```

Any caller can learn about the misconfiguration, and the wrong status hides it from the operator. Failures also never reach `onError`, so there is no signal in monitoring.

**Fix:**

| Error | Status | Body |
| --- | --- | --- |
| Signature, timestamp, missing header | 401 | Generic message |
| `WebhookPayloadError` | 400 | Generic message |
| `WebhookConfigurationError`, unexpected errors | 500 | Generic message |

Send all of them to `onError`.

#### Low-severity security items

| ID | Finding | Evidence | Fix |
| --- | --- | --- | --- |
| S8 | The URL used for Twilio and HubSpot is inferred from `Host`, `req.protocol`, or absolute-form `req.url` (`src/hookguard.ts:115-126`). All are client-influenced, which weakens binding to your endpoint and allows cross-endpoint replay of a captured signature. | Reproduced | Require a configured public base URL and combine it with the request path. |
| S9 | Discord skips the freshness check for a non-numeric timestamp (`src/providers/discord.ts:19`). It needs a valid signature, so it is not practically reachable, but it is inconsistent with Slack and Clerk. | Reproduced | Reject as malformed. |
| S10 | GitHub falls back to SHA-1 when the SHA-256 header is absent (`src/providers/github.ts:21`). Not a forgery risk today; GitHub marks the header legacy. A bad SHA-256 with a good SHA-1 is correctly rejected. | Reproduced | Make the fallback opt-in. |
| S11 | Zoho `algorithm` is not validated at runtime: `md5` is accepted, and an unknown value raises a raw `TypeError` (`src/providers/zoho.ts:31`). | Reproduced | Allowlist the values. |
| S12 | `strategies[provider]` reads inherited keys, so `constructor`, `__proto__` or `toString` raise `TypeError` rather than `UnsupportedProviderError` (`src/providers/index.ts:42`). Fails closed, but matters if the provider comes from a route parameter. | Reproduced | Use `Object.hasOwn`. |

**Payload validation:** JSON must parse to an object, and parse errors are wrapped in `WebhookPayloadError`. There is no body size limit, which is acceptable for a library, but the README should cover it. `express.raw()` defaults to 100 KB, which may be too small for some providers' larger payloads.

---

## 3. Provider correctness

These are functional failures rather than security holes: authentic requests are rejected or handled incorrectly.

#### C1. High: real HubSpot batches are always rejected

**Reproduced. Vendor doc.** `src/providers/hubspot.ts:46`

HubSpot delivers a JSON **array** of up to 100 events. `parseJsonObject` rejects arrays, so a correctly signed delivery throws `WebhookPayloadError`, the middleware returns 401, and `verifyWebhook` returns `false`. The existing test uses a single object, so it passes.

**Fix:** accept arrays, and decide how to model batches (one event per item, or `event.payload` as a list).

#### C2. High: the middleware cannot complete Slack or Discord handshakes

**Reproduced. Vendor doc.** `src/hookguard.ts:71`, `src/providers/slack.ts:41`

| Scenario | Provider expects | HookGuard does |
| --- | --- | --- |
| Slack `url_verification` | HTTP 200 echoing `challenge` | `200 { received: true }` |
| Discord PING (`type: 1`) | PONG (`{ "type": 1 }`) | `200 { received: true }` |
| Slack slash commands (form-encoded) | Verified and parsed | `WebhookPayloadError`, despite valid signature |
| Discord interaction replies | A body from your handler | Response already sent |

Slack Events API URLs and Discord interaction endpoints therefore cannot be registered through `guard.middleware()`. The README lists both as supported without this limitation.

**Fix:** add provider-specific auto-responses for the handshakes, and parse Slack bodies by content type. Discord interactions and Slack commands need a way for handlers to supply the response.

#### C3. Medium: GitHub form-encoded webhooks are rejected

**Reproduced. Vendor doc.** `src/providers/github.ts:28`

GitHub can send `application/x-www-form-urlencoded`, with JSON in a `payload` field. The signature passes, then JSON parsing fails. **Fix:** check the content type and unwrap `payload`.

#### C4. Medium: Zoho verification covers only part of the documented scheme

**Code. Vendor doc.** `src/providers/zoho.ts:31`

The code hashes the raw body only. Zoho Billing's documentation builds the string from query parameters and form pairs, sorted by key and concatenated, with raw JSON appended. Hashing the body alone can match only a raw-JSON webhook with no query parameters or form pairs.

**Unverified items:** Zoho's page does not state the output encoding, and its docs describe only HMAC-SHA256, so the `algorithm` option has no documented basis. The Zoho Books and Zoho Sign doc pages I tried were unreachable, so the README's Books claim and the `x-zs-webhook-signature` implementation are unconfirmed. Test each with a real webhook before claiming support.

#### C5. Medium: HubSpot URIs are not decoded before signing

**Code. Vendor doc.** `src/providers/hubspot.ts:35`

HubSpot requires decoding a specific set of characters in the URI (`%3A %2F %3F %40 %21 %24 %27 %28 %29 %2A %2C %3B`). The code uses the URL as given, so URLs containing these sequences will fail. HubSpot's text and table disagree on `%3F`, so confirm that one against a real request.

#### C6. Medium: several Twilio URL paths fail on valid requests

**Reproduced, except port handling (Code, Vendor doc).** `src/hookguard.ts:42`, `:115-126`

| Scenario | Result |
| --- | --- |
| Static `config.url` with a JSON webhook | 401: the static URL lacks the per-request `bodySHA256` |
| App behind a TLS proxy (`req.protocol === "http"`) | 401: signature mismatch |
| URL with or without an explicit port | Not handled; Twilio's SDK tries both variants |

The fix for S8 (configured base URL plus request path) resolves the first two.

#### Low-severity correctness items

| ID | Finding | Evidence | Fix |
| --- | --- | --- | --- |
| C7 | Middleware replies with JSON to Twilio, while Twilio voice and messaging webhooks normally expect TwiML. | Code | Allow custom response bodies; document in the meantime. |
| C8 | README errors: the Twilio row says "URL + JSON body", but the code signs a URL containing `bodySHA256`. `verifyWebhook` is described as covering signature and header failures, but it also returns `false` for a valid signature with an unparseable body. | Code | Correct both. |

---

## 4. Reliability and enterprise readiness

### 4.1 Requested resilience patterns

HookGuard is an **inbound verification library**. It makes no outgoing HTTP calls, and a search of `src` for retry, backoff, jitter, circuit breaker, timeout and HTTP client usage found nothing.

| Pattern | Status | Assessment |
| --- | --- | --- |
| Exponential backoff | Absent | Not applicable; the provider retries |
| Retry mechanism | Absent | Not applicable to sending, but see R1: the library defeats provider retries |
| Jitter | Absent | Not applicable |
| Circuit breaker | Absent | Not applicable |
| Outgoing payload timeouts | Absent | Not applicable |
| Delivery tracking and status | Absent | Partly applicable: no delivery ID or lifecycle hooks (S5) |
| Handler timeouts | Absent | **Applicable: R3** |

**Recommendation:** do not add outbound features. They would make a focused zero-dependency package into a different product. State the scope in the README and fix the inbound equivalents below, because the provider's retry system is your resilience layer, and it only works if you report failures honestly.

### 4.2 Reliability findings

#### R1. High: events are acknowledged before processing, then lost on failure

**Reproduced.** `src/hookguard.ts:71-72`, `:85-89`

Observed order: `["status 200", "handler"]`. The provider has already received success when the handler runs, so a failure produces no retry and the event is gone. `onError` is optional, so without it, a handler error (`db down` in the test) is **discarded with no log at all**. In serverless runtimes, work after the response may also be frozen or never finish.

Acking early is reasonable for providers with short deadlines, but it needs to be a choice and it needs a durable hand-off.

**Fix:** add an `ack` option, such as `"after-handlers"` (return 5xx on failure so the provider retries) and `"immediate"`. Make `after-handlers` the default, and log to `console.error` when no `onError` is set. Document the queue-first pattern for slow work.

#### R2. High: a throwing `onError` becomes an unhandled rejection

**Reproduced (rejection). Crash behavior: Code.** `src/hookguard.ts:88`

If `onError` throws, the middleware's promise rejects (observed: `logger broke`). Express 4 does not handle rejected async middleware, and Node's default for unhandled rejections is to terminate the process. A logging failure during a handler failure could therefore take the server down. The rejection also skips remaining handlers.

**Fix:** wrap the `onError` call in `try/catch`, and forward unexpected errors to `next(err)`.

#### R3. Medium: handlers have no timeout or isolation

**Reproduced.** `src/hookguard.ts:79-92`

Handlers run sequentially, so a handler that never resolves blocks every later handler. In the test, the second handler never ran. **Fix:** add an optional `handlerTimeoutMs`, and consider `Promise.allSettled` for independent handlers.

### 4.3 Other operational gaps

- **Observability:** no hook for verification failures or successful deliveries (S7).
- **Secret rotation:** one secret per provider, so rotation means downtime. Accept `secret: string | string[]`.
- **`event.timestamp`** is the receipt time (`new Date()`), not the provider's time. Rename it to `receivedAt`, or document it.

---

## 5. Architecture, types and developer experience

### 5.1 Strengths

- `constructEvent` is a clear entry point with a familiar Stripe-style shape.
- The strategy-per-provider structure is small and makes adding providers easy.
- `tsconfig` is strict, including `noUncheckedIndexedAccess`.
- Native TypeScript output, with `.d.ts` files generated and `types` set correctly.
- Custom errors have stable `code` values, and the `verifyWebhook` boolean helper is useful.

### 5.2 Findings

#### D1. Medium: Fetch-standard inputs fail with a misleading error

**Reproduced.** `src/utils/headers.ts:9`

A Fetch `Headers` object has no enumerable entries, so `Object.entries` returns nothing. Correctly signed requests throw `MissingHeaderError`. This affects Next.js App Router, Hono, Bun and similar frameworks. `Uint8Array` and `ArrayBuffer` bodies work at runtime, but `RawBody` does not allow them in types.

**Fix:** accept `Headers` and widen `RawBody`.

#### D2. Medium: a parsed body gives a confusing failure, or passes by coincidence

**Reproduced.** `src/hookguard.ts:112`

`extractBody` runs `JSON.stringify` on parsed bodies. This is the most common webhook integration mistake, and the library reports it as `signature does not match`. A compact body re-serializes identically and passes, so the bug can survive testing and break later on a payload that re-serializes differently.

**Fix:** remove the fallback and throw `WebhookConfigurationError` with a message explaining the raw-body requirement.

#### D3. Low: error handling gaps

The custom hierarchy is good, but some paths still raise generic errors:

| Trigger | Currently raises | Should raise |
| --- | --- | --- |
| Wrong arguments (`src/verify.ts:92`, `:111`) | `TypeError` | `WebhookConfigurationError` |
| Object passed as body (`src/utils/request.ts:16`) | Node `TypeError` | `WebhookConfigurationError` |
| Unknown algorithm | Node `TypeError` | `WebhookConfigurationError` |
| Inherited provider key | `TypeError` | `UnsupportedProviderError` |
| Invalid Discord public key | `WebhookSignatureError` | `WebhookConfigurationError` |

Other improvements: export a union type for error codes, and pass `cause` when wrapping. With a dual build, advise checking `error.code` rather than `instanceof`, since CJS and ESM can load separate class copies.

#### D4. Low: type export gaps

- `HttpRequestLike`, `HttpResponseLike`, `NextFunctionLike` and `HeaderValue` appear in public signatures but are not exported from `src/index.ts`.
- `constructEvent` is not generic, although `WebhookEvent<TPayload>` is, so callers must cast (as `examples/express-demo.ts:22` does).
- `verifyWebhook` lacks the request-object overload that `constructEvent` has.
- Public types use `Buffer`, so TypeScript consumers need `@types/node`.

#### D5. Low: API rough edges

- The constructor accepts `new HookGuard()` and `secret: undefined`; misconfiguration appears only on the first request. Validate at startup.
- `callNext` runs after the response is sent, and the event is not attached to `req`, so downstream code can neither respond nor read it.
- `on("*")` does nothing, and `push.*` does not match bare `push` (reproduced). Support a catch-all and document the matching rules.
- `res.status().json()` works with Express but not Fastify, despite the framework-neutral `HttpRequestLike` naming.
- `buildWebhookEvent` duplicates `constructEvent`; consider dropping it before 1.0, since removing it later is a breaking change.
- `examples/express-demo.ts:7-8` falls back to hardcoded secrets. Example code gets copied, so fail if the variable is unset.
- `src/providers/twilio.ts:1` imports `crypto`, while other files use `node:crypto`. Duplicated helpers (`pickString`) could be shared.

### 5.3 Test coverage gaps

No test covers: repeated form keys, `tolerance` validation, array or form bodies, Clerk rejection (Clerk has one test, a success case), stale Discord timestamps, handler failure or `onError`, or middleware status mapping. Coverage is not measured, and there are no fixtures from real provider deliveries, which is why C1 to C5 went unnoticed. Fixtures captured from real deliveries would be the most valuable addition.

---

## 6. npm publishing and distribution

### 6.1 Blockers

#### P1. Blocker: the name `hookguard` is owned by another maintainer

**Reproduced via `npm view`.** `hookguard` on npm is an unrelated React hooks analysis tool by maintainer `quack_`, created 2025-05-13, latest version `1.1.16`. Publishing to that name will be refused. Local checks, including `npm pack`, will not show this.

**Use a scoped name**, such as `@<your-npm-username>/hookguard`, with `"publishConfig": { "access": "public" }`. It keeps the brand and avoids npm's similarity rules.

| Unscoped candidate | Registry result |
| --- | --- |
| `webhookguard` | Taken |
| `webhook-guard` | Free, but likely refused as too similar to `webhookguard` |
| `hook-guard` | Free, but likely refused as too similar to `hookguard` |
| `hookguard-webhooks`, `hookguardjs` | Free |

"Likely refused" reflects npm's similarity check, which I have not tested. `npm whoami` shows this machine is not logged in, so your scope could not be checked.

#### P2. Blocker: a third-party package is listed as a dependency

**Reproduced.** `package.json` declares `"dependencies": { "hookguard": "^1.1.16" }`.

This is not a self-reference; it is the package from P1. It was most likely added by a stray `npm install hookguard`. Nothing in `src` uses it. Every consumer of this security library would install an unrelated package plus `ts-morph`, `commander` and `tsconfig-paths`, and future releases within that range would be picked up automatically. It is the source of all 4 production audit warnings, and it makes the "zero-dependency" claim false.

It is in the lockfile but missing from local `node_modules`, so your tests pass without it. A clean `npm ci` would install it.

**Fix:** `npm uninstall hookguard`, then confirm the lockfile has no entry.

#### P3. Blocker: the license is not shipped

**Reproduced.** The file is misspelled `LICENSCE`, so npm does not auto-include it, and the `npm pack` listing does not contain it. The MIT license requires its notice to accompany copies. **Fix:** `git mv LICENSCE LICENSE`.

#### P4. Blocker: `dist/` is stale and the build does not clean it

**Reproduced.** `dist/` dates from 2026-10-18.

| Issue | Files |
| --- | --- |
| In `dist`, not in `src` (would ship) | `core/verifySignature`, `providers/verify` |
| In `src`, not in `dist` | `providers/zohosign` |

`prepublishOnly` rebuilds, so `zohosign` would appear after a publish, but `tsc` never deletes old files, so the two orphans would still ship. A plain `npm pack` would ship the whole stale build, as `prepublishOnly` does not run for it.

**Fix:** add a `clean` step, and run the build from `prepack` so that it also covers `npm pack`.

### 6.2 `package.json` review

| Field | Status | Notes |
| --- | --- | --- |
| `name` | **Fail** | P1 |
| `version` | Review | Free under a new name. Consider `0.x` until tested against live providers, because `1.0.0` promises API stability and section 5 proposes breaking changes. |
| `description`, `keywords`, `license` | Pass | Remove "Zero-dependency" only if P2 is not fixed |
| `main` | Pass | Points to ESM; right for an ESM-only package, change for dual |
| `module` | Absent | Not required with `exports`; add only for dual builds |
| `exports` | Partial | ESM only; no `require` condition (P5) |
| `types` | Pass | Listed first in `exports`, as required |
| `files` | Pass | Whitelist works; tests and `src` excluded; shipping stale content is P4 |
| `engines` | Review | See below |
| `dependencies` | **Fail** | P2. Should be empty |
| `devDependencies` | Review | See 6.4 |
| `peerDependencies` | Remove | `src` never imports `express`; the optional peer is misleading |
| `repository`, `homepage`, `bugs`, `author` | **Missing** | Needed for provenance and for users to report vulnerabilities |
| `sideEffects` | Missing | Add `false` |
| `exports["./package.json"]` | Missing | Add for tooling |
| `publishConfig` | Missing | Required for a public scoped package |

**`engines`:** `>=18` is untested, as everything here ran on Node 22.14. Node 18 and 20 are past end of life at this audit date. Raise the floor to `>=20` or `>=22`, and test what you declare in CI.

**Source maps:** the 40 `.map` files point at `src/`, which is not shipped. Add `src` to `files`, or disable `sourceMap` and `declarationMap`.

### 6.3 P5. Medium: no dual CommonJS/ESM support

**Reproduced.**

| Environment | `require()` result |
| --- | --- |
| Node 22.14, default | Works through `require(esm)` |
| `require(esm)` disabled | `ERR_REQUIRE_ESM` |
| `attw`, node16 from CJS | Warning: dynamic import only |

**Recommendation:** since you listed dual support as a requirement, build with `tsup`, which is a dev dependency only:

```json
{
  "type": "module",
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": { "types": "./dist/index.d.ts", "default": "./dist/index.js" },
      "require": { "types": "./dist/index.d.cts", "default": "./dist/index.cjs" }
    },
    "./package.json": "./package.json"
  }
}
```

ESM-only is a defensible alternative if `engines` is raised to versions with `require(esm)` enabled. If you choose it, say so in the README.

### 6.4 Development dependency audit

`npm audit` reports critical and high advisories in `vitest`, `tinypool`, `vite`, `proxy-addr` and `body-parser`. These come through dev tools and do not reach consumers, but they do run on your machine and in CI. Upgrade `vitest` and `express`, then re-run the audit. `vitest` needs a major upgrade, so expect some test tooling changes.

### 6.5 README and project files

| Item | Status | Notes |
| --- | --- | --- |
| README.md | Good base | Install, quick start, provider table and error list are all present |
| Quick start | Partial | The raw-body warning is good, but there is no complete try/catch example; `WebhookSignatureError` is imported and unused; the Express snippet omits `import express` |
| Provider list | Inaccurate | Line 5 omits Zoho Sign; C1, C2, C4 limitations are not stated |
| Security best practices | **Missing** | See below |
| Scope statement | Missing | State that this is inbound verification only |
| LICENSE | **Fail** | P3 |
| CHANGELOG.md | Missing | |
| SECURITY.md | Missing | Essential for a security library: how to report privately |
| CONTRIBUTING.md | Missing | Optional at launch |
| CI workflow | Missing | Run typecheck, tests, build, `publint`, `attw` across Node versions |
| Lint and format | Missing | Inconsistent indentation in `zohosign.ts` and `hookGuard.test.ts` |

**The README security section should cover:** keeping raw bodies, using HTTPS, deduplicating by event ID, which providers have no replay window, which fields are not signed, secret storage and rotation, failing startup when a secret is missing, and setting the public URL behind proxies.

---

## 7. Finalization checklist

The commands below work in PowerShell, one per line. Replace `@your-scope/hookguard` with your chosen name.

### Phase 1: Decisions

- [ ] Choose the package name (P1), and confirm you own the scope.
- [ ] Choose dual build or ESM-only (P5).
- [ ] Choose the Node floor (section 6.2).
- [ ] Choose the first version: `0.x` until provider testing is done, or `1.0.0`.
- [ ] Choose the default acknowledgement behavior (R1). This is a breaking choice, so decide before the first release.

### Phase 2: Packaging fixes

- [ ] Remove the third-party dependency (P2):
  ```powershell
  npm uninstall hookguard
  ```
- [ ] Rename the license file (P3):
  ```powershell
  git mv LICENSCE LICENSE
  ```
- [ ] Update `package.json`: `name`, `version`, `repository`, `homepage`, `bugs`, `author`, `sideEffects`, `publishConfig`, `engines`. Remove `peerDependencies`.
- [ ] Add clean builds (P4):
  ```json
  "clean": "node -e \"require('node:fs').rmSync('dist',{recursive:true,force:true})\"",
  "build": "npm run clean && tsc -p tsconfig.json",
  "prepack": "npm run build",
  "prepublishOnly": "npm run typecheck && npm test"
  ```
  Adjust `build` if you adopt `tsup`.
- [ ] Decide on source maps (ship `src` or disable them).

### Phase 3: Security and correctness fixes

Add a regression test with each fix, written to fail first.

- [ ] **S1** Sign all repeated Twilio values; keep arrays in `parseFormBody`.
- [ ] **S2** Validate `tolerance`.
- [ ] **S3** Validate Clerk secrets strictly.
- [ ] **R1** Add acknowledgement modes and default error logging.
- [ ] **R2** Guard `onError`.
- [ ] **C1** Accept HubSpot arrays.
- [ ] **C2** Handle Slack and Discord handshakes and Slack form bodies.
- [ ] **S7** Map errors to the correct status, use generic messages, report to `onError`.
- [ ] **S6** Scope handlers by provider.
- [ ] **S5** Add `event.id` and a deduplication hook.
- [ ] **S4** Document unsigned fields.
- [ ] **C3–C6** Fix GitHub form bodies, Zoho string building, HubSpot URI decoding, Twilio URL handling.
- [ ] **D1, D2** Support Fetch `Headers`; reject parsed bodies.
- [ ] **R3** and the low-severity items, or file them as tracked issues.

### Phase 4: Live provider verification

- [ ] Capture one real delivery per provider, and store it as a sanitized test fixture.
- [ ] Confirm the unverified Zoho items: output encoding, Zoho Books, and the Zoho Sign header and encoding (C4).
- [ ] Confirm HubSpot's `%3F` handling (C5).
- [ ] Remove any provider from the README that you could not confirm.

### Phase 5: Documentation

- [ ] Update the README: scope statement, security section, limitations, corrected table, full quick start, new package name.
- [ ] Add `CHANGELOG.md` and `SECURITY.md`.
- [ ] Add a CI workflow.

### Phase 6: Local build verification

- [ ] Clean install from the lockfile:
  ```powershell
  npm ci
  ```
- [ ] Confirm there are no runtime dependencies. The `dependencies` field should be empty or absent:
  ```powershell
  npm ls --omit=dev --all
  npm audit --omit=dev
  ```
- [ ] Run the quality gates:
  ```powershell
  npm run typecheck
  npm test
  npm run build
  ```
- [ ] Update dev dependencies and re-run `npm audit`.
- [ ] Inspect the tarball. Confirm `LICENSE` is listed, `providers/zohosign` is present, and `core/verifySignature` and `providers/verify` are gone:
  ```powershell
  npm pack --dry-run
  ```
- [ ] Lint the package. Create the tarball, then pass its filename to `attw`:
  ```powershell
  npm pack
  npx publint
  npx @arethetypeswrong/cli .\your-tarball-name.tgz
  ```
- [ ] Test as a real consumer, outside the repository:
  ```powershell
  New-Item -ItemType Directory ..\hookguard-smoke
  Set-Location ..\hookguard-smoke
  npm init -y
  npm install ..\hookguard\your-tarball-name.tgz
  node --input-type=module -e "import('@your-scope/hookguard').then(m => console.log(Object.keys(m)))"
  node -e "console.log(Object.keys(require('@your-scope/hookguard')))"
  Set-Location ..\hookguard
  ```
- [ ] Delete the tarball and the smoke-test folder.

### Phase 7: Safe dry run

- [ ] Confirm the name is yours to use. A 404 means an unscoped name is free; for a scope, you must own it:
  ```powershell
  npm view @your-scope/hookguard
  ```
- [ ] Log in and confirm the account:
  ```powershell
  npm login
  npm whoami
  ```
- [ ] Confirm a clean tree on the intended commit:
  ```powershell
  git status
  ```
- [ ] Run the dry run. It uploads nothing:
  ```powershell
  npm publish --dry-run
  ```
- [ ] Check the output: name, version, file list, size, `access`, and that there is no `.env`, `tests`, or stale file. Expect a tarball close to the 20 KB measured here, and be suspicious of a large change.

A passing dry run does not prove the registry will accept the name, which is why the `npm view` step comes first.

### Phase 8: Release (only after everything above passes)

- [ ] Enable two-factor authentication on the npm account.
- [ ] Tag the release, and publish from CI with `--provenance` if you can; it suits a security library.
- [ ] After publishing, install from the registry in a clean folder and repeat the smoke test.

---

## Appendix: Sources

**Vendor documentation and source**

- [Twilio: Webhooks security](https://www.twilio.com/docs/usage/webhooks/webhooks-security)
- [twilio-node: webhooks.ts](https://raw.githubusercontent.com/twilio/twilio-node/main/src/webhooks/webhooks.ts)
- [HubSpot: Validating requests](https://developers.hubspot.com/docs/api/webhooks/validating-requests)
- [HubSpot: Working with webhooks](https://developers.hubspot.com/docs/platform/working-with-webhooks)
- [Zoho Billing: Securing webhooks](https://www.zoho.com/billing/kb/webhooks/securing-webhooks.html)
- [GitHub: Validating webhook deliveries](https://docs.github.com/en/webhooks/securing)
- [Slack: Using HTTP request URLs](https://docs.slack.dev/apis/events-api/using-http-request-urls/)

**Third-party references** (official pages were not retrieved for these points)

- [Hookdeck: Guide to HubSpot webhooks](https://hookdeck.com/webhooks/platforms/guide-to-hubspot-webhooks-features-and-best-practices), for the 100-event batch limit
- [Discord PING and PONG handling](https://dev.to/sendotltd/discord-slash-commands-without-an-sdk-ed25519-in-250-lines-of-typescript-208l)

**Not retrievable:** Zoho Books and Zoho Sign webhook pages.
