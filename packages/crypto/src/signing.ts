import { canonicalStringify } from "./canonical";
import { hmacSha256Hex, timingSafeEqualHex, sha256Hex } from "./hash";

/** Sign a canonical body with HMAC-SHA256 using the given key (hex). */
export function signCanonical(key: string | Buffer, body: unknown): string {
  return hmacSha256Hex(key, canonicalStringify(body));
}

/** Sign an already-canonicalized string. */
export function signString(key: string | Buffer, canonical: string): string {
  return hmacSha256Hex(key, canonical);
}

/** Verify a signature over a canonical body in constant time. */
export function verifySignature(
  key: string | Buffer,
  body: unknown,
  signature: string,
): boolean {
  const expected = signCanonical(key, body);
  return timingSafeEqualHex(signature, expected);
}

/** Verify a signature over an already-canonicalized string. */
export function verifySignatureString(
  key: string | Buffer,
  canonical: string,
  signature: string,
): boolean {
  const expected = signString(key, canonical);
  return timingSafeEqualHex(signature, expected);
}

export { canonicalStringify, sha256Hex };

/** Build a canonical hash of an input object (used for ticket parameter binding). */
export function inputHash(input: unknown): string {
  return sha256Hex(canonicalStringify(input));
}
