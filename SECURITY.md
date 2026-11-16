# Security Policy

HookGuard verifies webhook signatures, so a bug here can let a forged request
through. Reports are taken seriously.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

Before 1.0, fixes ship in the latest 0.x release only.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub's vulnerability reporting form:
https://github.com/AbayleE/hookGuard/security/advisories/new

Include:

- the provider involved (Stripe, GitHub, and so on);
- a minimal reproduction, such as a body, headers, and the secret used to sign
  them, or a description of the configuration that is accepted when it should
  not be;
- the HookGuard version.

You should receive an acknowledgement within seven days. Once a fix is
released, the advisory is published with credit to the reporter unless you
prefer otherwise.

## In scope

- Signature or timestamp checks that accept a request they should reject
- Timing side channels in signature comparison
- Configuration mistakes that are silently accepted instead of throwing
- Idempotency keys that an unauthenticated caller can influence

## Out of scope

- Vulnerabilities in the providers' own webhook schemes
- Handlers or application code that call HookGuard incorrectly, unless the
  documentation led to the mistake
