import { UnsupportedProviderError } from "../errors.js";
import type {
  NormalizedRequest,
  ProviderName,
  VerifyOptions,
  WebhookEvent,
} from "../types.js";
import { decodeClerkSecret, parseClerkEvent, verifyClerk } from "./clerk.js";
import {
  assertDiscordPublicKey,
  parseDiscordEvent,
  verifyDiscord,
} from "./discord.js";
import { parseGitHubEvent, verifyGitHub } from "./github.js";
import { parseHubSpotEvent, verifyHubSpot } from "./hubspot.js";
import { parseShopifyEvent, verifyShopify } from "./shopify.js";
import { parseSlackEvent, verifySlack } from "./slack.js";
import { parseStripeEvent, verifyStripe } from "./stripe.js";
import { parseTwilioEvent, verifyTwilio } from "./twilio.js";
import { parseZohoEvent, verifyZoho } from "./zoho.js";
import { parseZohoSignEvent, verifyZohoSign } from "./zohosign.js";

export type ProviderStrategy = {
  verify: (
    request: NormalizedRequest,
    secret: string,
    options: VerifyOptions
  ) => void;
  parse: (request: NormalizedRequest) => WebhookEvent;
  /** Throws WebhookConfigurationError for a secret that can never be valid. */
  validateSecret?: (secret: string) => void;
};

const strategies: Record<ProviderName, ProviderStrategy> = {
  stripe: { verify: verifyStripe, parse: parseStripeEvent },
  github: { verify: verifyGitHub, parse: parseGitHubEvent },
  shopify: { verify: verifyShopify, parse: parseShopifyEvent },
  slack: { verify: verifySlack, parse: parseSlackEvent },
  twilio: { verify: verifyTwilio, parse: parseTwilioEvent },
  zoho: { verify: verifyZoho, parse: parseZohoEvent },
  hubspot: { verify: verifyHubSpot, parse: parseHubSpotEvent },
  clerk: {
    verify: verifyClerk,
    parse: parseClerkEvent,
    validateSecret: decodeClerkSecret,
  },
  discord: {
    verify: verifyDiscord,
    parse: parseDiscordEvent,
    validateSecret: assertDiscordPublicKey,
  },
  zohosign: { verify: verifyZohoSign, parse: parseZohoSignEvent },
};

export function getProviderStrategy(provider: string): ProviderStrategy {
  if (!Object.hasOwn(strategies, provider)) {
    throw new UnsupportedProviderError(provider);
  }
  return strategies[provider as ProviderName];
}
