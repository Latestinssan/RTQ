/**
 * Ed25519 device identity primitives.
 *
 * The mobile approval protocol uses Ed25519 (RFC 8032) rather than HMAC for
 * device approvals. HMAC requires the verifier to hold the same secret as the
 * signer, which means the host would have to know every device's private key —
 * impossible for a device key that never leaves the device. Ed25519 gives the
 * device a private key it alone holds, and the host only stores the public key.
 *
 * Keys are represented as JWK (`{"kty":"OKP","crv":"Ed25519","x":...}`) so the
 * same representation can be produced/consumed by Node and by the Dart
 * `cryptography` package.
 *
 * Signatures are deterministic RFC 8032 signatures, so the TypeScript and Dart
 * implementations produce byte-identical signatures for identical keys and
 * messages. `protocol/rtq-approval-v1.vectors.json` pins that agreement.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type JsonWebKey,
  type KeyObject,
} from "crypto";

export interface Ed25519KeyPair {
  /** Public key JWK — safe to publish / register with the host. */
  publicKeyJwk: JsonWebKey;
  /** Private key JWK — MUST stay in device secure storage. Never transmit. */
  privateKeyJwk: JsonWebKey;
}

/** Generate a fresh Ed25519 key pair. */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyJwk: publicKey.export({ format: "jwk" }) as JsonWebKey,
    privateKeyJwk: privateKey.export({ format: "jwk" }) as JsonWebKey,
  };
}

function isKeyObject(value: JsonWebKey | KeyObject): value is KeyObject {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as KeyObject).export === "function" &&
    (value as KeyObject).type === "public"
  );
}

function isPrivateKeyObject(value: JsonWebKey | KeyObject): value is KeyObject {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as KeyObject).export === "function" &&
    (value as KeyObject).type === "private"
  );
}

/** Import an Ed25519 private key JWK into a Node KeyObject. */
export function importEd25519PrivateKey(jwk: JsonWebKey): KeyObject {
  return createPrivateKey({ key: jwk, format: "jwk" });
}

/** Import an Ed25519 public key JWK into a Node KeyObject. */
export function importEd25519PublicKey(jwk: JsonWebKey): KeyObject {
  return createPublicKey({ key: jwk, format: "jwk" });
}

function publicJwk(value: JsonWebKey | KeyObject): JsonWebKey {
  if (isKeyObject(value)) {
    return value.export({ format: "jwk" }) as JsonWebKey;
  }
  return value;
}

/**
 * Raw 32-byte Ed25519 public key. This is the canonical device identity
 * material; `deviceId` is the SHA-256 of exactly these bytes.
 */
export function ed25519PublicKeyBytes(value: JsonWebKey | KeyObject): Buffer {
  const jwk = publicJwk(value);
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("not an Ed25519 public key JWK");
  }
  const bytes = Buffer.from(jwk.x, "base64url");
  if (bytes.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

/** Base64url-encoded raw public key (wire form embedded in challenges). */
export function ed25519PublicKeyBase64Url(
  value: JsonWebKey | KeyObject,
): string {
  return ed25519PublicKeyBytes(value).toString("base64url");
}

/**
 * Device ID = SHA-256 hex of the raw 32-byte public key. The host recomputes
 * this from the registered public key, so a device cannot claim an arbitrary
 * ID: the ID *is* the key fingerprint.
 */
export function deviceIdFromPublicKey(value: JsonWebKey | KeyObject): string {
  return createHash("sha256")
    .update(ed25519PublicKeyBytes(value))
    .digest("hex");
}

/** Build a JWK from a base64url raw public key (used when parsing pairing data). */
export function ed25519PublicKeyJwkFromBase64Url(x: string): JsonWebKey {
  const bytes = Buffer.from(x, "base64url");
  if (bytes.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${bytes.length}`);
  }
  return { kty: "OKP", crv: "Ed25519", x: bytes.toString("base64url") };
}

/** Sign a message with an Ed25519 private key; returns a 64-byte hex signature. */
export function ed25519Sign(
  privateKey: JsonWebKey | KeyObject,
  message: string | Buffer,
): string {
  const key = isPrivateKeyObject(privateKey)
    ? privateKey
    : importEd25519PrivateKey(privateKey);
  const data =
    typeof message === "string" ? Buffer.from(message, "utf8") : message;
  return cryptoSign(null, data, key).toString("hex");
}

/** Verify an Ed25519 signature (hex). Returns false on any malformed input. */
export function ed25519Verify(
  publicKey: JsonWebKey | KeyObject,
  message: string | Buffer,
  signatureHex: string,
): boolean {
  try {
    if (
      typeof signatureHex !== "string" ||
      !/^[0-9a-fA-F]{128}$/.test(signatureHex)
    ) {
      return false;
    }
    const key = isKeyObject(publicKey)
      ? publicKey
      : importEd25519PublicKey(publicKey);
    const data =
      typeof message === "string" ? Buffer.from(message, "utf8") : message;
    return cryptoVerify(null, data, key, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}
