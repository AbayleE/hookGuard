export class HookGuardError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
  }
}

export class WebhookSignatureError extends HookGuardError {
  constructor(message = "Webhook signature verification failed") {
    super(message, "SIGNATURE_VERIFICATION_FAILED");
  }
}

export class WebhookTimestampError extends HookGuardError {
  constructor(message = "Webhook timestamp is outside the allowed tolerance window") {
    super(message, "TIMESTAMP_OUT_OF_TOLERANCE");
  }
}

export class MissingHeaderError extends HookGuardError {
  readonly header: string;

  constructor(header: string) {
    super(`Missing required webhook header: ${header}`, "MISSING_HEADER");
    this.header = header;
  }
}

export class UnsupportedProviderError extends HookGuardError {
  readonly provider: string;

  constructor(provider: string) {
    super(`Unsupported webhook provider: ${provider}`, "UNSUPPORTED_PROVIDER");
    this.provider = provider;
  }
}

export class WebhookPayloadError extends HookGuardError {
  constructor(message = "Failed to parse webhook payload") {
    super(message, "INVALID_PAYLOAD");
  }
}

export class WebhookConfigurationError extends HookGuardError {
  constructor(message: string) {
    super(message, "INVALID_CONFIGURATION");
  }
}
