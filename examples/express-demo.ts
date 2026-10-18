import express from "express";
import { constructEvent, HookGuard } from "../src/index.js";

const app = express();
app.use(express.raw({ type: "application/json" }));

const stripeSecret = process.env.STRIPE_WEBHOOK_SECRET ?? "whsec_test";
const githubSecret = process.env.GITHUB_WEBHOOK_SECRET ?? "my-github-secret";

const guard = new HookGuard({
  providers: {
    stripe: { secret: stripeSecret },
    github: { secret: githubSecret },
  },
  onError: (err, event) => {
    console.error(`Handler error for ${event?.type}:`, err.message);
  },
});

guard
  .on("payment_intent.succeeded", async (event) => {
    const pi = event.payload as { id?: string; amount?: number };
    console.log(`Payment succeeded: ${pi.id}`);
  })
  .on("push", async (event) => {
    console.log(`GitHub push`, event.payload);
  })
  .on("pull_request.*", async (event) => {
    console.log(`PR event: ${event.type}`);
  });

app.post("/webhooks/stripe", guard.middleware("stripe"));
app.post("/webhooks/github", guard.middleware("github"));

app.post("/webhooks/stripe-fn", (req, res) => {
  try {
    const event = constructEvent("stripe", req.body, req.headers, stripeSecret);
    res.status(200).json({ type: event.type });
  } catch (error) {
    res.status(401).json({
      error: error instanceof Error ? error.message : "invalid",
    });
  }
});

app.listen(3000, () => {
  console.log("HookGuard listening on http://localhost:3000");
});
