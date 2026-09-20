/**
 * `rtq-approval-v1` — the versioned QR / mobile approval protocol.
 *
 * This module is deliberately independent of Flutter, of HTTP, and of any
 * particular host UI. It defines the bytes on the wire and the exact rules for
 * accepting or rejecting them. The Dart implementation in `apps/rtq-mobile`
 * implements the same rules and shares the test vectors in
 * `protocol/rtq-approval-v1.vectors.json`.
 *
 * Design rules enforced here:
 *  - The QR carries NO secret and NO pre-baked approval. It is a challenge.
 *  - The host signs the challenge, so the device can detect a spoofed QR whose
 *    displayed risk/operation was tampered with before it ever shows a button.
 *  - The device signs a compact binding of the challenge; the host re-checks
 *    every security-critical field against its own pending state.
 *  - Unknown protocol versions are rejected, never "best-effort" parsed.
 *  - JSON is parsed strictly (duplicate keys rejected) so two implementations
 *    cannot disagree about which value a payload means.
 */

import {
  canonicalStringify,
  deviceIdFromPublicKey,
  ed25519PublicKeyBase64Url,
  ed25519PublicKeyBytes,
  ed25519Sign,
  ed25519Verify,
  nonce as randomNonce,
  strictJsonParse,
  StrictJsonError,
  uuidV4,
  type Ed25519KeyPair,
} from "@rtq/crypto";
import type { JsonWebKey } from "crypto";
import type { Origin, RiskLevel } from "@rtq/core";
import { RISK_LEVELS } from "@rtq/core";
import { PROTOCOL_ERROR, fail, ok, type ParseResult } from "./errors";

export const RTQ_APPROVAL_PROTOCOL = "rtq-approval-v1" as const;
export const RTQ_APPROVAL_PROTOCOL_VERSION = 1 as const;

/**
 * QR prefixes. `rtq://challenge?v=1&c=` is the canonical challenge prefix and
 * is also accepted as `rtq://approval?v=1&c=`. Pairing uses `rtq://pair?v=1&c=`.
 */
export const CHALLENGE_QR_PREFIX = "rtq://challenge?v=1&c=";
export const APPROVAL_QR_PREFIX = "rtq://approval?v=1&c=";
export const PAIRING_QR_PREFIX = "rtq://pair?v=1&c=";

export const CHALLENGE_TTL_MS_V1 = 5 * 60 * 1000;
export const PAIRING_TTL_MS_V1 = 2 * 60 * 1000;
export const CLOCK_SKEW_MS_V1 = 60 * 1000;

const ORIGINS: readonly Origin[] = [
  "local",
  "remote",
  "mobile",
  "plugin",
  "agent",
  "automation",
  "unknown",
];

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;

// ===========================================================================
// Types
// ===========================================================================

/** A challenge before the host signature is attached. */
export interface UnsignedChallengeV1 {
  protocol: typeof RTQ_APPROVAL_PROTOCOL;
  version: typeof RTQ_APPROVAL_PROTOCOL_VERSION;
  kind: "challenge";
  challengeId: string;
  capability: string;
  capabilityVersion: number;
  /** SHA-256 hex of the canonicalized operation input. */
  inputHash: string;
  /** Human-readable description of the exact operation. Display-only. */
  summary: Record<string, unknown>;
  risk: RiskLevel;
  policyVersion: string;
  origin: Origin;
  /** Application requesting the operation (e.g. "RTQ Desktop"). */
  application: string;
  /** Stable host identity. */
  hostId: string;
  /** Raw Ed25519 host public key, base64url (32 bytes). */
  hostPublicKey: string;
  expiresAt: number;
  nonce: string;
}

/** The challenge as encoded in the QR: unsigned body + host signature. */
export interface ChallengeV1 extends UnsignedChallengeV1 {
  /** Ed25519 hex signature by the host over `challengeSigningBody`. */
  hostSignature: string;
}

/** A pairing challenge before the host signature is attached. */
export interface UnsignedPairingChallengeV1 {
  protocol: typeof RTQ_APPROVAL_PROTOCOL;
  version: typeof RTQ_APPROVAL_PROTOCOL_VERSION;
  kind: "pairing";
  pairingId: string;
  hostId: string;
  hostPublicKey: string;
  application: string;
  /** Optional human hint describing which host is asking to pair. */
  userHint?: string;
  expiresAt: number;
  nonce: string;
}

export interface PairingChallengeV1 extends UnsignedPairingChallengeV1 {
  hostSignature: string;
}

/** The subset of a challenge that the device signs as its approval binding. */
export interface ApprovalBindingV1 {
  challengeId: string;
  capability: string;
  capabilityVersion: number;
  inputHash: string;
  risk: RiskLevel;
  origin: Origin;
  application: string;
  hostId: string;
  policyVersion: string;
  expiresAt: number;
  nonce: string;
}

export interface UnsignedApprovalV1 {
  protocol: typeof RTQ_APPROVAL_PROTOCOL;
  version: typeof RTQ_APPROVAL_PROTOCOL_VERSION;
  kind: "approval";
  challenge: ApprovalBindingV1;
  decision: "granted" | "denied";
  deviceId: string;
  signedAt: number;
}

export interface SignedApprovalV1 extends UnsignedApprovalV1 {
  /** Ed25519 hex signature by the device over `approvalSigningBody`. */
  signature: string;
}

export interface UnsignedPairingResponseV1 {
  protocol: typeof RTQ_APPROVAL_PROTOCOL;
  version: typeof RTQ_APPROVAL_PROTOCOL_VERSION;
  kind: "pairing_response";
  pairingId: string;
  hostId: string;
  nonce: string;
  deviceId: string;
  deviceName: string;
  publicKeyJwk: JsonWebKey;
  signedAt: number;
}

export interface SignedPairingResponseV1 extends UnsignedPairingResponseV1 {
  deviceSignature: string;
}

// ===========================================================================
// Canonical signing bodies
// ===========================================================================

/** The exact canonical bytes the host signs for a challenge. */
export function challengeSigningBody(challenge: UnsignedChallengeV1): string {
  return canonicalStringify({
    protocol: challenge.protocol,
    version: challenge.version,
    kind: challenge.kind,
    challengeId: challenge.challengeId,
    capability: challenge.capability,
    capabilityVersion: challenge.capabilityVersion,
    inputHash: challenge.inputHash,
    summary: challenge.summary,
    risk: challenge.risk,
    policyVersion: challenge.policyVersion,
    origin: challenge.origin,
    application: challenge.application,
    hostId: challenge.hostId,
    hostPublicKey: challenge.hostPublicKey,
    expiresAt: challenge.expiresAt,
    nonce: challenge.nonce,
  });
}

/** The exact canonical bytes the host signs for a pairing challenge. */
export function pairingSigningBody(
  challenge: UnsignedPairingChallengeV1,
): string {
  return canonicalStringify({
    protocol: challenge.protocol,
    version: challenge.version,
    kind: challenge.kind,
    pairingId: challenge.pairingId,
    hostId: challenge.hostId,
    hostPublicKey: challenge.hostPublicKey,
    application: challenge.application,
    userHint: challenge.userHint ?? null,
    expiresAt: challenge.expiresAt,
    nonce: challenge.nonce,
  });
}

/** The exact canonical bytes the device signs for an approval. */
export function approvalSigningBody(approval: UnsignedApprovalV1): string {
  return canonicalStringify({
    protocol: approval.protocol,
    version: approval.version,
    kind: approval.kind,
    challenge: {
      challengeId: approval.challenge.challengeId,
      capability: approval.challenge.capability,
      capabilityVersion: approval.challenge.capabilityVersion,
      inputHash: approval.challenge.inputHash,
      risk: approval.challenge.risk,
      origin: approval.challenge.origin,
      application: approval.challenge.application,
      hostId: approval.challenge.hostId,
      policyVersion: approval.challenge.policyVersion,
      expiresAt: approval.challenge.expiresAt,
      nonce: approval.challenge.nonce,
    },
    decision: approval.decision,
    deviceId: approval.deviceId,
    signedAt: approval.signedAt,
  });
}

/** The exact canonical bytes a device signs when completing pairing. */
export function pairingResponseSigningBody(
  response: UnsignedPairingResponseV1,
): string {
  return canonicalStringify({
    protocol: response.protocol,
    version: response.version,
    kind: response.kind,
    pairingId: response.pairingId,
    hostId: response.hostId,
    nonce: response.nonce,
    deviceId: response.deviceId,
    deviceName: response.deviceName,
    publicKeyJwk: {
      kty: response.publicKeyJwk.kty,
      crv: response.publicKeyJwk.crv,
      x: response.publicKeyJwk.x,
    },
    signedAt: response.signedAt,
  });
}

/** Extract the signed binding from a verified challenge. */
export function challengeToBinding(challenge: ChallengeV1): ApprovalBindingV1 {
  return {
    challengeId: challenge.challengeId,
    capability: challenge.capability,
    capabilityVersion: challenge.capabilityVersion,
    inputHash: challenge.inputHash,
    risk: challenge.risk,
    origin: challenge.origin,
    application: challenge.application,
    hostId: challenge.hostId,
    policyVersion: challenge.policyVersion,
    expiresAt: challenge.expiresAt,
    nonce: challenge.nonce,
  };
}

// ===========================================================================
// Encode
// ===========================================================================

function encodeBase64Url(value: unknown): string {
  return Buffer.from(canonicalStringify(value), "utf8").toString("base64url");
}

export function encodeChallengeV1(challenge: ChallengeV1): string {
  return CHALLENGE_QR_PREFIX + encodeBase64Url(challenge);
}

export function encodePairingChallengeV1(
  challenge: PairingChallengeV1,
): string {
  return PAIRING_QR_PREFIX + encodeBase64Url(challenge);
}

/** Canonical JSON for a signed approval (the POST body). */
export function encodeSignedApprovalV1(approval: SignedApprovalV1): string {
  return canonicalStringify(approval);
}

/** Canonical JSON for a pairing response (the POST body). */
export function encodePairingResponseV1(
  response: SignedPairingResponseV1,
): string {
  return canonicalStringify(response);
}

// ===========================================================================
// Decode / strict parse helpers
// ===========================================================================

function decodeEnvelope(payload: string, prefix: string): ParseResult<unknown> {
  if (typeof payload !== "string") {
    return fail(PROTOCOL_ERROR.INVALID_PREFIX, "payload is not a string");
  }
  if (!payload.startsWith(prefix)) {
    return fail(
      PROTOCOL_ERROR.INVALID_PREFIX,
      `payload does not start with "${prefix}"`,
    );
  }
  const encoded = payload.slice(prefix.length);
  if (encoded.length === 0 || !B64URL.test(encoded)) {
    return fail(
      PROTOCOL_ERROR.MALFORMED_BASE64,
      "payload is not canonical base64url",
    );
  }
  let text: string;
  try {
    text = Buffer.from(encoded, "base64url").toString("utf8");
  } catch {
    return fail(PROTOCOL_ERROR.MALFORMED_BASE64, "base64url decode failed");
  }
  // Re-encode to reject non-canonical encodings (padding, aliases).
  if (Buffer.from(text, "utf8").toString("base64url") !== encoded) {
    return fail(
      PROTOCOL_ERROR.MALFORMED_BASE64,
      "payload is not canonical base64url",
    );
  }
  try {
    return ok(strictJsonParse(text));
  } catch (error) {
    if (error instanceof StrictJsonError) {
      const code = /duplicate object key/i.test(error.message)
        ? PROTOCOL_ERROR.DUPLICATE_JSON_KEY
        : PROTOCOL_ERROR.MALFORMED_JSON;
      return fail(code, error.message);
    }
    return fail(PROTOCOL_ERROR.MALFORMED_JSON, "payload is not valid JSON");
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isFiniteInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

function isRiskLevel(value: unknown): value is RiskLevel {
  return (
    typeof value === "string" &&
    (RISK_LEVELS as readonly string[]).includes(value)
  );
}

function isOrigin(value: unknown): value is Origin {
  return (
    typeof value === "string" && (ORIGINS as readonly string[]).includes(value)
  );
}

function isHostPublicKey(value: unknown): value is string {
  if (typeof value !== "string" || !B64URL.test(value)) return false;
  try {
    return (
      ed25519PublicKeyBytes(
        // reuse the length check without importing createPublicKey
        { kty: "OKP", crv: "Ed25519", x: value },
      ).length === 32
    );
  } catch {
    return false;
  }
}

// ===========================================================================
// Challenge parse + verify
// ===========================================================================

interface ParsedEnvelope {
  protocol: unknown;
  version: unknown;
  kind: unknown;
  raw: Record<string, unknown>;
}

function parseCommon(
  payload: string,
  prefixes: readonly string[],
): ParseResult<ParsedEnvelope> {
  let decoded: ParseResult<unknown> | null = null;
  for (const prefix of prefixes) {
    const attempt = decodeEnvelope(payload, prefix);
    if (attempt.ok) {
      decoded = attempt;
      break;
    }
    // Remember the most specific failure for a matching prefix.
    if (typeof payload === "string" && payload.startsWith(prefix)) {
      decoded = attempt;
      break;
    }
  }
  if (!decoded) {
    return fail(
      PROTOCOL_ERROR.INVALID_PREFIX,
      `payload does not start with a known prefix (${prefixes.join(", ")})`,
    );
  }
  if (!decoded.ok) return decoded;
  const raw = asRecord(decoded.value);
  if (!raw) {
    return fail(
      PROTOCOL_ERROR.PAYLOAD_NOT_OBJECT,
      "payload must be a JSON object",
    );
  }
  if (raw.protocol !== RTQ_APPROVAL_PROTOCOL) {
    return fail(
      PROTOCOL_ERROR.UNSUPPORTED_PROTOCOL,
      `unsupported protocol "${String(raw.protocol)}"`,
    );
  }
  if (raw.version !== RTQ_APPROVAL_PROTOCOL_VERSION) {
    return fail(
      PROTOCOL_ERROR.UNSUPPORTED_VERSION,
      `unsupported protocol version "${String(raw.version)}"`,
    );
  }
  return ok({
    protocol: raw.protocol,
    version: raw.version,
    kind: raw.kind,
    raw,
  });
}

/** Parse and structurally validate a challenge QR payload. */
export function parseChallengeV1(payload: string): ParseResult<ChallengeV1> {
  const env = parseCommon(payload, [CHALLENGE_QR_PREFIX, APPROVAL_QR_PREFIX]);
  if (!env.ok) return env;
  if (env.value.kind !== "challenge") {
    return fail(
      PROTOCOL_ERROR.UNKNOWN_KIND,
      `expected kind "challenge", got "${String(env.value.kind)}"`,
    );
  }
  const c = env.value.raw;
  if (
    !isNonEmptyString(c.challengeId) ||
    !isNonEmptyString(c.capability) ||
    !isFiniteInteger(c.capabilityVersion) ||
    typeof c.inputHash !== "string" ||
    !HEX64.test(c.inputHash) ||
    asRecord(c.summary) === null ||
    !isNonEmptyString(c.policyVersion) ||
    !isNonEmptyString(c.application) ||
    !isNonEmptyString(c.hostId) ||
    !isNonEmptyString(c.nonce) ||
    c.nonce.length < 16 ||
    !isFiniteInteger(c.expiresAt) ||
    !isRiskLevel(c.risk) ||
    !isOrigin(c.origin) ||
    !isHostPublicKey(c.hostPublicKey) ||
    typeof c.hostSignature !== "string" ||
    !HEX128.test(c.hostSignature)
  ) {
    return fail(
      PROTOCOL_ERROR.INVALID_FIELD,
      "challenge has a missing or invalid required field",
    );
  }
  const challenge: ChallengeV1 = {
    protocol: RTQ_APPROVAL_PROTOCOL,
    version: RTQ_APPROVAL_PROTOCOL_VERSION,
    kind: "challenge",
    challengeId: c.challengeId,
    capability: c.capability,
    capabilityVersion: c.capabilityVersion,
    inputHash: c.inputHash,
    summary: c.summary as Record<string, unknown>,
    risk: c.risk,
    policyVersion: c.policyVersion,
    origin: c.origin,
    application: c.application,
    hostId: c.hostId,
    hostPublicKey: c.hostPublicKey,
    expiresAt: c.expiresAt,
    nonce: c.nonce,
    hostSignature: c.hostSignature,
  };
  return ok(challenge);
}

/** Parse and structurally validate a pairing QR payload. */
export function parsePairingChallengeV1(
  payload: string,
): ParseResult<PairingChallengeV1> {
  const env = parseCommon(payload, [PAIRING_QR_PREFIX]);
  if (!env.ok) return env;
  if (env.value.kind !== "pairing") {
    return fail(
      PROTOCOL_ERROR.UNKNOWN_KIND,
      `expected kind "pairing", got "${String(env.value.kind)}"`,
    );
  }
  const c = env.value.raw;
  if (
    !isNonEmptyString(c.pairingId) ||
    !isNonEmptyString(c.hostId) ||
    !isNonEmptyString(c.application) ||
    !isNonEmptyString(c.nonce) ||
    c.nonce.length < 16 ||
    !isFiniteInteger(c.expiresAt) ||
    !isHostPublicKey(c.hostPublicKey) ||
    typeof c.hostSignature !== "string" ||
    !HEX128.test(c.hostSignature) ||
    (c.userHint !== undefined && typeof c.userHint !== "string")
  ) {
    return fail(
      PROTOCOL_ERROR.INVALID_FIELD,
      "pairing challenge has a missing or invalid required field",
    );
  }
  const pairing: PairingChallengeV1 = {
    protocol: RTQ_APPROVAL_PROTOCOL,
    version: RTQ_APPROVAL_PROTOCOL_VERSION,
    kind: "pairing",
    pairingId: c.pairingId,
    hostId: c.hostId,
    hostPublicKey: c.hostPublicKey,
    application: c.application,
    expiresAt: c.expiresAt,
    nonce: c.nonce,
    hostSignature: c.hostSignature,
  };
  if (typeof c.userHint === "string") pairing.userHint = c.userHint;
  return ok(pairing);
}

/**
 * Verify the host's Ed25519 signature over a challenge. When
 * `pinnedHostPublicKey` is supplied (a previously paired host), the challenge's
 * embedded key MUST match it, so a malicious QR cannot impersonate the host.
 */
export function verifyHostSignatureV1(
  challenge: UnsignedChallengeV1 & { hostSignature: string },
  pinnedHostPublicKey?: string,
): boolean {
  if (
    pinnedHostPublicKey !== undefined &&
    challenge.hostPublicKey !== pinnedHostPublicKey
  ) {
    return false;
  }
  try {
    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: challenge.hostPublicKey,
    } as JsonWebKey;
    return ed25519Verify(
      jwk,
      challengeSigningBody(challenge),
      challenge.hostSignature,
    );
  } catch {
    return false;
  }
}

/** Verify the host's Ed25519 signature over a pairing challenge. */
export function verifyPairingHostSignatureV1(
  pairing: UnsignedPairingChallengeV1 & { hostSignature: string },
  pinnedHostPublicKey?: string,
): boolean {
  if (
    pinnedHostPublicKey !== undefined &&
    pairing.hostPublicKey !== pinnedHostPublicKey
  ) {
    return false;
  }
  try {
    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: pairing.hostPublicKey,
    } as JsonWebKey;
    return ed25519Verify(
      jwk,
      pairingSigningBody(pairing),
      pairing.hostSignature,
    );
  } catch {
    return false;
  }
}

// ===========================================================================
// Create (host side)
// ===========================================================================

export interface CreateChallengeV1Params {
  challenge: {
    capability: string;
    capabilityVersion: number;
    inputHash: string;
    summary: Record<string, unknown>;
    risk: RiskLevel;
    policyVersion: string;
    origin: Origin;
  };
  host: {
    hostId: string;
    application: string;
    /** Ed25519 private key that signs challenges (JWK or KeyObject). */
    hostPrivateKey: Parameters<typeof ed25519Sign>[0];
    /** Public key matching `hostPrivateKey`. */
    hostPublicKey: JsonWebKey;
  };
  ttlMs?: number;
  challengeId?: string;
  nonce?: string;
  /** Fixed clock injection for deterministic tests. */
  now?: number;
}

/** Build and host-sign a challenge. */
export function createChallengeV1(
  params: CreateChallengeV1Params,
): ChallengeV1 {
  const unsigned: UnsignedChallengeV1 = {
    protocol: RTQ_APPROVAL_PROTOCOL,
    version: RTQ_APPROVAL_PROTOCOL_VERSION,
    kind: "challenge",
    challengeId: params.challengeId ?? uuidV4(),
    capability: params.challenge.capability,
    capabilityVersion: params.challenge.capabilityVersion,
    inputHash: params.challenge.inputHash,
    summary: params.challenge.summary,
    risk: params.challenge.risk,
    policyVersion: params.challenge.policyVersion,
    origin: params.challenge.origin,
    application: params.host.application,
    hostId: params.host.hostId,
    hostPublicKey: ed25519PublicKeyBase64Url(params.host.hostPublicKey),
    expiresAt:
      (params.now ?? Date.now()) + (params.ttlMs ?? CHALLENGE_TTL_MS_V1),
    nonce: params.nonce ?? randomNonce(),
  };
  return {
    ...unsigned,
    hostSignature: ed25519Sign(
      params.host.hostPrivateKey,
      challengeSigningBody(unsigned),
    ),
  };
}

export interface CreatePairingChallengeV1Params {
  host: {
    hostId: string;
    application: string;
    hostPrivateKey: Parameters<typeof ed25519Sign>[0];
    hostPublicKey: JsonWebKey;
  };
  userHint?: string;
  ttlMs?: number;
  pairingId?: string;
  nonce?: string;
  now?: number;
}

/** Build and host-sign a pairing challenge. */
export function createPairingChallengeV1(
  params: CreatePairingChallengeV1Params,
): PairingChallengeV1 {
  const unsigned: UnsignedPairingChallengeV1 = {
    protocol: RTQ_APPROVAL_PROTOCOL,
    version: RTQ_APPROVAL_PROTOCOL_VERSION,
    kind: "pairing",
    pairingId: params.pairingId ?? uuidV4(),
    hostId: params.host.hostId,
    hostPublicKey: ed25519PublicKeyBase64Url(params.host.hostPublicKey),
    application: params.host.application,
    expiresAt: (params.now ?? Date.now()) + (params.ttlMs ?? PAIRING_TTL_MS_V1),
    nonce: params.nonce ?? randomNonce(),
  };
  if (params.userHint !== undefined) unsigned.userHint = params.userHint;
  return {
    ...unsigned,
    hostSignature: ed25519Sign(
      params.host.hostPrivateKey,
      pairingSigningBody(unsigned),
    ),
  };
}

// ===========================================================================
// Approval sign + verify
// ===========================================================================

export interface SignApprovalV1Params {
  challenge: ChallengeV1;
  decision: "granted" | "denied";
  /** Device Ed25519 key pair. The private key never leaves the device. */
  deviceKeyPair: Ed25519KeyPair;
  signedAt?: number;
}

/**
 * Device-side: build a signed approval binding the exact challenge fields.
 * The signature is deterministic (RFC 8032), so the vectors are byte-exact.
 */
export function signApprovalV1(params: SignApprovalV1Params): SignedApprovalV1 {
  const deviceId = deviceIdFromPublicKey(params.deviceKeyPair.publicKeyJwk);
  const unsigned: UnsignedApprovalV1 = {
    protocol: RTQ_APPROVAL_PROTOCOL,
    version: RTQ_APPROVAL_PROTOCOL_VERSION,
    kind: "approval",
    challenge: challengeToBinding(params.challenge),
    decision: params.decision,
    deviceId,
    signedAt: params.signedAt ?? Date.now(),
  };
  return {
    ...unsigned,
    signature: ed25519Sign(
      params.deviceKeyPair.privateKeyJwk,
      approvalSigningBody(unsigned),
    ),
  };
}

/**
 * Verify the device signature and that the claimed `deviceId` is really the
 * fingerprint of the signing key. This is a pure cryptographic check; the host
 * MUST additionally verify the device is authorized and the binding matches a
 * live challenge (`MobileApprovalVerifier`).
 */
export function verifyApprovalSignatureV1(
  approval: SignedApprovalV1,
  publicKeyJwk: JsonWebKey,
): boolean {
  try {
    const expectedId = deviceIdFromPublicKey(publicKeyJwk);
    if (expectedId !== approval.deviceId) return false;
    return ed25519Verify(
      publicKeyJwk,
      approvalSigningBody(approval),
      approval.signature,
    );
  } catch {
    return false;
  }
}

/** Device-side: build a signed pairing response (proves key possession). */
export function signPairingResponseV1(params: {
  pairing: PairingChallengeV1;
  deviceName: string;
  deviceKeyPair: Ed25519KeyPair;
  signedAt?: number;
}): SignedPairingResponseV1 {
  const deviceId = deviceIdFromPublicKey(params.deviceKeyPair.publicKeyJwk);
  const unsigned: UnsignedPairingResponseV1 = {
    protocol: RTQ_APPROVAL_PROTOCOL,
    version: RTQ_APPROVAL_PROTOCOL_VERSION,
    kind: "pairing_response",
    pairingId: params.pairing.pairingId,
    hostId: params.pairing.hostId,
    nonce: params.pairing.nonce,
    deviceId,
    deviceName: params.deviceName,
    publicKeyJwk: params.deviceKeyPair.publicKeyJwk,
    signedAt: params.signedAt ?? Date.now(),
  };
  return {
    ...unsigned,
    deviceSignature: ed25519Sign(
      params.deviceKeyPair.privateKeyJwk,
      pairingResponseSigningBody(unsigned),
    ),
  };
}

/** Host-side: verify a pairing response's device signature + ID fingerprint. */
export function verifyPairingResponseV1(
  response: SignedPairingResponseV1,
): boolean {
  try {
    const expectedId = deviceIdFromPublicKey(response.publicKeyJwk);
    if (expectedId !== response.deviceId) return false;
    return ed25519Verify(
      response.publicKeyJwk,
      pairingResponseSigningBody(response),
      response.deviceSignature,
    );
  } catch {
    return false;
  }
}

/** Strictly parse a signed approval (POST body) with duplicate-key rejection. */
export function parseSignedApprovalV1(
  text: string,
): ParseResult<SignedApprovalV1> {
  return parseSignedObject<SignedApprovalV1>(text, "approval");
}

/** Strictly parse a signed pairing response (POST body). */
export function parsePairingResponseV1(
  text: string,
): ParseResult<SignedPairingResponseV1> {
  return parseSignedObject<SignedPairingResponseV1>(text, "pairing_response");
}

function parseSignedObject<T>(
  text: string,
  expectedKind: string,
): ParseResult<T> {
  let raw: unknown;
  try {
    raw = strictJsonParse(text);
  } catch (error) {
    if (error instanceof StrictJsonError) {
      const code = /duplicate object key/i.test(error.message)
        ? PROTOCOL_ERROR.DUPLICATE_JSON_KEY
        : PROTOCOL_ERROR.MALFORMED_JSON;
      return fail(code, error.message);
    }
    return fail(PROTOCOL_ERROR.MALFORMED_JSON, "not valid JSON");
  }
  const record = asRecord(raw);
  if (!record) {
    return fail(PROTOCOL_ERROR.PAYLOAD_NOT_OBJECT, "payload must be an object");
  }
  if (record.protocol !== RTQ_APPROVAL_PROTOCOL) {
    return fail(PROTOCOL_ERROR.UNSUPPORTED_PROTOCOL, "unsupported protocol");
  }
  if (record.version !== RTQ_APPROVAL_PROTOCOL_VERSION) {
    return fail(PROTOCOL_ERROR.UNSUPPORTED_VERSION, "unsupported version");
  }
  if (record.kind !== expectedKind) {
    return fail(PROTOCOL_ERROR.UNKNOWN_KIND, `expected kind "${expectedKind}"`);
  }
  return validateSigned(record, expectedKind);
}

function validateSigned<T>(
  record: Record<string, unknown>,
  kind: string,
): ParseResult<T> {
  if (kind === "approval") {
    const challenge = asRecord(record.challenge);
    if (
      !challenge ||
      !isNonEmptyString(challenge.challengeId) ||
      !isNonEmptyString(challenge.capability) ||
      !isFiniteInteger(challenge.capabilityVersion) ||
      typeof challenge.inputHash !== "string" ||
      !HEX64.test(challenge.inputHash) ||
      !isRiskLevel(challenge.risk) ||
      !isOrigin(challenge.origin) ||
      !isNonEmptyString(challenge.application) ||
      !isNonEmptyString(challenge.hostId) ||
      !isNonEmptyString(challenge.policyVersion) ||
      !isFiniteInteger(challenge.expiresAt) ||
      !isNonEmptyString(challenge.nonce) ||
      (record.decision !== "granted" && record.decision !== "denied") ||
      typeof record.deviceId !== "string" ||
      !HEX64.test(record.deviceId) ||
      !isFiniteInteger(record.signedAt) ||
      typeof record.signature !== "string" ||
      !HEX128.test(record.signature)
    ) {
      return fail(
        PROTOCOL_ERROR.INVALID_FIELD,
        "approval has a missing or invalid required field",
      );
    }
    return ok(record as unknown as T);
  }
  if (kind === "pairing_response") {
    const jwk = asRecord(record.publicKeyJwk);
    if (
      !jwk ||
      jwk.kty !== "OKP" ||
      jwk.crv !== "Ed25519" ||
      typeof jwk.x !== "string" ||
      !isNonEmptyString(record.pairingId) ||
      !isNonEmptyString(record.hostId) ||
      !isNonEmptyString(record.nonce) ||
      typeof record.deviceId !== "string" ||
      !HEX64.test(record.deviceId) ||
      !isNonEmptyString(record.deviceName) ||
      !isFiniteInteger(record.signedAt) ||
      typeof record.deviceSignature !== "string" ||
      !HEX128.test(record.deviceSignature)
    ) {
      return fail(
        PROTOCOL_ERROR.INVALID_FIELD,
        "pairing response has a missing or invalid required field",
      );
    }
    return ok(record as unknown as T);
  }
  return fail(PROTOCOL_ERROR.UNKNOWN_KIND, `unknown object kind "${kind}"`);
}

/** True when the payload looks like any `rtq://` QR this app understands. */
export function isSupportedRtqQr(payload: string): boolean {
  return (
    typeof payload === "string" &&
    (payload.startsWith(CHALLENGE_QR_PREFIX) ||
      payload.startsWith(APPROVAL_QR_PREFIX) ||
      payload.startsWith(PAIRING_QR_PREFIX))
  );
}
