import { createHmac } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
    constructEvent,
    HookGuard,
    verifyWebhook,
    WebhookConfigurationError,
} from "../src/index.js";

const SECRET = "test-secret";

function githubRequest(event: string, payload: object) {
    const body = JSON.stringify(payload);
    const digest = createHmac("sha256", SECRET).update(body).digest("hex");
    return {
        body: Buffer.from(body),
        headers: {
            "x-hub-signature-256": `sha256=${digest}`,
            "x-github-event": event,
        },
    };
}

function fakeRes() {
    const res = {
        statusCode: 0,
        body: undefined as unknown,
        status(code: number) {
            res.statusCode = code;
            return {
                json(b: unknown) {
                    res.body = b;
                },
            };
        },
    };
    return res;
}

function makeGuard() {
    return new HookGuard({ providers: { github: { secret: SECRET } } });
}

describe("wildcard handlers", () => {
    it("matches pull_request.* but not pull_request_review.*", async () => {
        const guard = makeGuard();
        const handler = vi.fn();
        guard.on("pull_request.*", handler);
        const mw = guard.middleware("github");

        await mw(githubRequest("pull_request", { action: "opened" }), fakeRes(), vi.fn());
        expect(handler).toHaveBeenCalledTimes(1);

        await mw(
            githubRequest("pull_request_review", { action: "submitted" }),
            fakeRes(),
            vi.fn()
        );
        expect(handler).toHaveBeenCalledTimes(1); // still 1
    });
});

describe("middleware", () => {
    it("does not call next() by default", async () => {
        const next = vi.fn();
        const res = fakeRes();
        await makeGuard().middleware("github")(
            githubRequest("push", { ref: "refs/heads/main" }),
            res,
            next
        );
        expect(res.statusCode).toBe(200);
        expect(next).not.toHaveBeenCalled();
    });

    it("calls next() when callNext is true", async () => {
        const next = vi.fn();
        await makeGuard().middleware("github", { callNext: true })(
            githubRequest("push", { ref: "refs/heads/main" }),
            fakeRes(),
            next
        );
        expect(next).toHaveBeenCalledTimes(1);
    });

    it("rejects a bad signature with 401", async () => {
        const req = githubRequest("push", {});
        req.headers["x-hub-signature-256"] = `sha256=${"00".repeat(32)}`;
        const res = fakeRes();
        await makeGuard().middleware("github")(req, res, vi.fn());
        expect(res.statusCode).toBe(401);
    });
});

describe("empty secret", () => {
    it("constructEvent throws a configuration error", () => {
        const req = githubRequest("push", {});
        expect(() => constructEvent("github", req.body, req.headers, "")).toThrow(
            WebhookConfigurationError
        );
    });

    it("verifyWebhook surfaces it instead of returning false", () => {
        const req = githubRequest("push", {});
        expect(() => verifyWebhook("github", req.body, req.headers, "")).toThrow(
            WebhookConfigurationError
        );
    });
});