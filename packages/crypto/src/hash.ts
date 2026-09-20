import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "crypto";

/** SHA-256 hex digest of a UTF-8 string. */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** HMAC-SHA-256 hex digest. */
export function hmacSha256Hex(key: string | Buffer, input: string): string {
  return createHmac("sha256", key).update(input, "utf8").digest("hex");
}

/**
 * Compare two hex digests in constant time. Returns false when lengths
 * differ or either value is empty, without leaking length information beyond
 * what is inherently observable via an empty-value shortcut.
 */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length === 0 || b.length === 0) return false;
  const bufA = Buffer.from(a, "hex");
  const bufB = Buffer.from(b, "hex");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/** 32 random bytes, hex-encoded (unguessable). */
export function randomHex(bytes = 32): string {
  return randomBytes(bytes).toString("hex");
}

/** RFC 4122 v4 UUID. */
export function uuidV4(): string {
  return randomUUID();
}

/** Ephemeral nonce: 128 bits of randomness, hex-encoded. */
export function nonce(): string {
  return randomHex(16);
}

/** Derive a deterministic key id (like a key fingerprint) for a secret key. */
export function keyId(secret: string | Buffer): string {
  return sha256Hex(`rtq:key:${secret}`);
}
