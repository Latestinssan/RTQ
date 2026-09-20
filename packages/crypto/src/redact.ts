/**
 * Redaction of secrets for audit logging and error reporting.
 *
 * Rules:
 *  - Structural redaction: known secret field names are replaced with
 *    `[REDACTED]` regardless of value.
 *  - Pattern redaction: strings matching high-signal secret patterns
 *    (bearer tokens, API keys, PEM private keys, long base64-ish runs) are
 *    replaced with `[REDACTED]`.
 *  - Deep redaction: nested objects and arrays are traversed.
 *  - The original object is never mutated (a copy is returned).
 */

export const SECRET_FIELD_NAMES: ReadonlySet<string> = new Set([
  "password",
  "passwd",
  "pin",
  "pins",
  "pincode",
  "passcode",
  "apiKey",
  "api_key",
  "apiKeyId",
  "apikey",
  "authToken",
  "auth_token",
  "accessToken",
  "access_token",
  "refreshToken",
  "refresh_token",
  "bearer",
  "bearerToken",
  "clientSecret",
  "client_secret",
  "privateKey",
  "private_key",
  "secret",
  "secretKey",
  "secret_key",
  "sessionId",
  "session_id",
  "sessionSecret",
  "session_secret",
  "token",
  "webhookSecret",
  "webhook_secret",
  "cookie",
  "credentials",
  "credential",
  "mfa",
  "totp",
  "oneTimeCode",
  "otp",
  "twoFactorCode",
  "authorization",
]);

const REDACTED = "[REDACTED]";

const PEM_BLOCK =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const BEARER = /\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b/gi;
const AWS_ACCESS_KEY = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;
const GENERIC_API_KEY =
  /\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*["']?[A-Za-z0-9\-._~+/]{8,}["']?/gi;
const LONG_SECRET_RUN = /\b[A-Za-z0-9\-._~+/]{40,}\b/g;

/** Redact a string by replacing secret-bearing substrings. */
export function redactString(
  input: string,
  extraSecretValues: ReadonlySet<string> = new Set(),
): string {
  if (!input) return input;
  let out = input
    .replace(PEM_BLOCK, REDACTED)
    .replace(BEARER, REDACTED)
    .replace(AWS_ACCESS_KEY, REDACTED)
    .replace(GENERIC_API_KEY, REDACTED);

  for (const value of extraSecretValues) {
    if (value && value.length >= 6) {
      out = out.split(value).join(REDACTED);
    }
  }

  // Long secret-shaped runs only when they are not plain words (a 40+ char
  // alphanumeric run is nearly always a key or digest).
  out = out.replace(LONG_SECRET_RUN, REDACTED);
  return out;
}

/** Recursively redact a JSON-serializable value. */
export function redactValue(
  input: unknown,
  extraSecretValues: ReadonlySet<string> = new Set(),
): unknown {
  if (input === null || input === undefined) return input;
  if (typeof input === "string") {
    return redactString(input, extraSecretValues);
  }
  if (typeof input === "number" || typeof input === "boolean") return input;
  if (Array.isArray(input)) {
    return input.map((item) => redactValue(item, extraSecretValues));
  }
  if (typeof input === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(
      input as Record<string, unknown>,
    )) {
      const folded = key.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (SECRET_FIELD_NAMES.has(key) || SECRET_FIELD_NAMES.has(folded)) {
        out[key] = REDACTED;
      } else {
        out[key] = redactValue(value, extraSecretValues);
      }
    }
    return out;
  }
  return REDACTED;
}

/** Redact a value and serialize it deterministically (for audit payloads). */
export function redactCanonicalJson(
  input: unknown,
  extraSecretValues: ReadonlySet<string> = new Set(),
): string {
  const redacted = redactValue(input, extraSecretValues);
  return JSON.stringify(redacted);
}

export { REDACTED };
