// Runs the middleware in a real Express server over HTTP, because fake request
// and response objects cannot show how Express parses and sends data.
import { createHmac } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { HookGuard, type HttpRequestLike } from "../src/index.js";

const SECRET = "test-secret";
const twilioUrl = "https://public.example/webhooks/twilio";
const handler = vi.fn();
const onError = vi.fn();

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const guard = new HookGuard({
    providers: {
      github: { secret: SECRET },
      slack: { secret: SECRET },
      twilio: { secret: SECRET, url: twilioUrl },
    },
    onError,
  });
  guard.on("github", "push", handler);

  const app = express();
  app.use("/webhooks", express.raw({ type: "*/*" }));
  app.post("/webhooks/github", guard.middleware("github"));
  app.post("/webhooks/slack", guard.middleware("slack"));
  app.post("/webhooks/twilio", guard.middleware("twilio"));
  app.post(
    "/webhooks/next",
    guard.middleware("github", { callNext: true }),
    (req, res) => {
      res.json({ type: (req as HttpRequestLike).webhookEvent?.type });
    }
  );
  app.post("/parsed", express.json(), guard.middleware("github"));

  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

function postGitHub(path: string, body: string, signature?: string) {
  const digest = createHmac("sha256", SECRET).update(body).digest("hex");
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-github-event": "push",
      "x-hub-signature-256": signature ?? `sha256=${digest}`,
    },
    body,
  });
}

describe("Express integration", () => {
  it("verifies a request and runs its handler", async () => {
    handler.mockClear();
    // Spacing and escapes that JSON.stringify would not reproduce.
    const response = await postGitHub("/webhooks/github", '{ "ref" : "caf\\u00e9" }');

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true });
    expect(handler).toHaveBeenCalledOnce();
    expect(handler.mock.calls[0]?.[0].payload).toEqual({ ref: "café" });
  });

  it("rejects a forged signature", async () => {
    handler.mockClear();
    const response = await postGitHub(
      "/webhooks/github",
      "{}",
      `sha256=${"00".repeat(32)}`
    );

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "Invalid webhook" });
    expect(handler).not.toHaveBeenCalled();
  });

  it("returns 500 and explains why when the body was already parsed", async () => {
    onError.mockClear();
    const response = await postGitHub("/parsed", '{"a":1}');

    expect(response.status).toBe(500);
    expect(await response.text()).not.toContain("raw");
    expect(onError.mock.calls[0]?.[0].message).toContain("express.raw");
  });

  it("passes the event along with callNext", async () => {
    const response = await postGitHub("/webhooks/next", "{}");

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ type: "push" });
  });

  it("completes the Slack URL handshake", async () => {
    const body = '{"type":"url_verification","challenge":"abc"}';
    const timestamp = String(Math.floor(Date.now() / 1000));
    const digest = createHmac("sha256", SECRET)
      .update(`v0:${timestamp}:${body}`)
      .digest("hex");

    const response = await fetch(`${baseUrl}/webhooks/slack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-slack-request-timestamp": timestamp,
        "x-slack-signature": `v0=${digest}`,
      },
      body,
    });

    expect(await response.json()).toEqual({ challenge: "abc" });
  });

  it("replies to Twilio with XML, using the configured public URL", async () => {
    const signature = createHmac("sha1", SECRET)
      .update(`${twilioUrl}Bodyhello`)
      .digest("base64");

    const response = await fetch(`${baseUrl}/webhooks/twilio`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "x-twilio-signature": signature,
      },
      body: "Body=hello",
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/xml");
    expect(await response.text()).toBe("<Response/>");
  });
});
