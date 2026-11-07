export type HookGuardErrorCode =
  | "SIGNATURE_VERIFICATION_FAILED"
  | "TIMESTAMP_OUT_OF_TOLERANCE"
  | "MISSING_HEADER"
  | "UNSUPPORTED_PROVIDER"
  | "INVALID_PAYLOAD"
  | "INVALID_CONFIGURATION"
  | "HANDLER_TIMEOUT";

export class HookGuardError extends Error {
  readonly code: HookGuardErrorCode;

  constructor(message: string, code: HookGuardErrorCode, options?: ErrorOptions) {
    super(message, options);
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
  constructor(message = "Failed to parse webhook payload", options?: ErrorOptions) {
    super(message, "INVALID_PAYLOAD", options);
  }
}

export class WebhookConfigurationError extends HookGuardError {
  constructor(message: string) {
    super(message, "INVALID_CONFIGURATION");
  }
}

export class WebhookHandlerTimeoutError extends HookGuardError {
  readonly timeoutMs: number;

  constructor(timeoutMs: number) {
    super(`Webhook handler did not finish within ${timeoutMs}ms`, "HANDLER_TIMEOUT");
    this.timeoutMs = timeoutMs;
  }
}
