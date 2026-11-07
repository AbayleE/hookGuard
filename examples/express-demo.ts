import express from "express";
import { constructEvent, HookGuard, HookGuardError } from "../src/index.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Set ${name} before starting the demo`);
  }
  return value;
}

const stripeSecret = requireEnv("STRIPE_WEBHOOK_SECRET");
const githubSecret = requireEnv("GITHUB_WEBHOOK_SECRET");

const app = express();
// Webhook routes need the raw bytes. Accepting every content type means a
// wrong header gets a 401, rather than reaching the route with no raw body.
app.use("/webhooks", express.raw({ type: "*/*" }));

const guard = new HookGuard({
  providers: {
    stripe: { secret: stripeSecret },
    github: { secret: githubSecret },
  },
  onError: (err, event) => {
    console.error(`Webhook error for ${event?.type ?? "rejected request"}:`, err.message);
  },
});

guard
  .on<{ id?: string }>("stripe", "payment_intent.succeeded", async (event) => {
    console.log(`Payment event: ${event.payload.id}`);
  })
  .on("github", "push", async (event) => {
    console.log("GitHub push", event.payload);
  })
  .on("github", "pull_request.*", async (event) => {
    console.log(`PR event: ${event.type}`);
  });

app.post("/webhooks/stripe", guard.middleware("stripe"));
app.post("/webhooks/github", guard.middleware("github"));

app.post("/webhooks/stripe-fn", (req, res) => {
  try {
    const event = constructEvent("stripe", req.body, req.headers, stripeSecret);
    res.status(200).json({ type: event.type });
  } catch (error) {
    if (error instanceof HookGuardError) {
      console.error(error.code, error.message);
    }
    res.status(401).json({ error: "Invalid webhook" });
  }
});

app.listen(3000, () => {
  console.log("HookGuard listening on http://localhost:3000");
});
