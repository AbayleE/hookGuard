import { UnsupportedProviderError } from "../errors.js";
import type {
  NormalizedRequest,
  ProviderName,
  VerifyOptions,
  WebhookEvent,
} from "../types.js";
import { parseClerkEvent, verifyClerk } from "./clerk.js";
import { parseDiscordEvent, verifyDiscord } from "./discord.js";
import { parseGitHubEvent, verifyGitHub } from "./github.js";
import { parseHubSpotEvent, verifyHubSpot } from "./hubspot.js";
import { parseShopifyEvent, verifyShopify } from "./shopify.js";
import { parseSlackEvent, verifySlack } from "./slack.js";
import { parseStripeEvent, verifyStripe } from "./stripe.js";
import { parseTwilioEvent, verifyTwilio } from "./twilio.js";
import { parseZohoEvent, verifyZoho } from "./zoho.js";
import { parseZohoSignEvent, verifyZohoSign } from "./zohosign.js";

type ProviderStrategy = {
  verify: (
    request: NormalizedRequest,
    secret: string,
    options: VerifyOptions
  ) => void;
  parse: (request: NormalizedRequest) => WebhookEvent;
};

const strategies: Record<ProviderName, ProviderStrategy> = {
  stripe: { verify: verifyStripe, parse: parseStripeEvent },
  github: { verify: verifyGitHub, parse: parseGitHubEvent },
  shopify: { verify: verifyShopify, parse: parseShopifyEvent },
  slack: { verify: verifySlack, parse: parseSlackEvent },
  twilio: { verify: verifyTwilio, parse: parseTwilioEvent },
  zoho: { verify: verifyZoho, parse: parseZohoEvent },
  hubspot: { verify: verifyHubSpot, parse: parseHubSpotEvent },
  clerk: { verify: verifyClerk, parse: parseClerkEvent },
  discord: { verify: verifyDiscord, parse: parseDiscordEvent },
  zohosign: { verify: verifyZohoSign, parse: parseZohoSignEvent },
};

export function getProviderStrategy(provider: string): ProviderStrategy {
  const strategy = strategies[provider as ProviderName];
  if (!strategy) {
    throw new UnsupportedProviderError(provider);
  }
  return strategy;
}

export {
  parseClerkEvent,
  parseDiscordEvent,
  parseGitHubEvent,
  parseHubSpotEvent,
  parseShopifyEvent,
  parseSlackEvent,
  parseStripeEvent,
  parseTwilioEvent,
  parseZohoEvent,
  parseZohoSignEvent,
  verifyClerk,
  verifyDiscord,
  verifyGitHub,
  verifyHubSpot,
  verifyShopify,
  verifySlack,
  verifyStripe,
  verifyTwilio,
  verifyZoho,
  verifyZohoSign
};
