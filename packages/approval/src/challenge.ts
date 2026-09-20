import type { ApprovalStrategy, Origin, RiskLevel } from "@rtq/core";
import {
  canonicalStringify,
  hmacSha256Hex,
  nonce,
  timingSafeEqualHex,
  uuidV4,
} from "@rtq/crypto";

/**
 * QR / mobile verification protocol (RTQ challenge-response).
 *
 * The QR payload is a short-lived, unpredictable CHALLENGE bound to the exact
 * operation. It is NOT an approval: scanning it grants nothing. A verifier
 * that has performed local authentication signs an approval with a
 * platform-protected device key, and the host verifies the signature over the
 * exact challenge. PINs are never transmitted.
 */

export interface ApprovalChallenge {
  /** Protocol version. */
  rtq: 1;
  challengeId: string;
  capability: string;
  capabilityVersion: number;
  /** SHA-256 of the canonicalized input that will be executed. */
  inputHash: string;
  /** Human-readable summary of the exact operation to be approved. */
  summary: Record<string, unknown>;
  risk: RiskLevel;
  policyVersion: string;
  origin: Origin;
  expiresAt: number;
  /** Ephemeral server nonce — unpredictable, single challenge. */
  nonce: string;
}

export interface DeviceApproval {
  challengeId: string;
  decision: "granted" | "denied";
  keyId: string;
  /** Unix epoch milliseconds. */
  signedAt: number;
  /** HMAC-SHA256 over the canonical approval body with the device key. */
  signature: string;
}

export interface DeviceApprovalBody {
  challengeId: string;
  decision: "granted" | "denied";
  keyId: string;
  signedAt: number;
}

export function approvalBody(approval: DeviceApprovalBody): string {
  return canonicalStringify({
    challengeId: approval.challengeId,
    decision: approval.decision,
    keyId: approval.keyId,
    signedAt: approval.signedAt,
  });
}

export const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const CHALLENGE_SKEW_MS = 60 * 1000; // allow 60s clock skew

/** Encode a challenge into the QR payload string. */
export function encodeChallenge(challenge: ApprovalChallenge): string {
  const body = Buffer.from(canonicalStringify(challenge), "utf8").toString(
    "base64url",
  );
  return `rtq://challenge?v=1&c=${body}`;
}

export type ChallengeParseResult =
  { ok: true; challenge: ApprovalChallenge } | { ok: false; reason: string };

interface RawChallengeLike {
  rtq?: unknown;
  challengeId?: unknown;
  capability?: unknown;
  capabilityVersion?: unknown;
  inputHash?: unknown;
  summary?: unknown;
  risk?: unknown;
  policyVersion?: unknown;
  origin?: unknown;
  expiresAt?: unknown;
  nonce?: unknown;
}

/** Parse and structurally validate a QR challenge payload. */
export function parseChallenge(payload: string): ChallengeParseResult {
  if (
    typeof payload !== "string" ||
    !payload.startsWith("rtq://challenge?v=1&c=")
  ) {
    return { ok: false, reason: "invalid payload prefix" };
  }
  const encoded = payload.slice("rtq://challenge?v=1&c=".length);
  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return { ok: false, reason: "payload is not valid JSON" };
  }
  if (raw === null || typeof raw !== "object") {
    return { ok: false, reason: "payload must be an object" };
  }
  const c = raw as RawChallengeLike;
  if (
    c.rtq !== 1 ||
    typeof c.challengeId !== "string" ||
    c.challengeId.length === 0 ||
    typeof c.capability !== "string" ||
    c.capability.length === 0 ||
    typeof c.capabilityVersion !== "number" ||
    !Number.isInteger(c.capabilityVersion) ||
    typeof c.inputHash !== "string" ||
    c.inputHash.length !== 64 ||
    typeof c.risk !== "string" ||
    typeof c.policyVersion !== "string" ||
    typeof c.expiresAt !== "number" ||
    typeof c.nonce !== "string" ||
    c.nonce.length < 16 ||
    c.summary === null ||
    typeof c.summary !== "object"
  ) {
    return { ok: false, reason: "challenge structure is invalid" };
  }
  return {
    ok: true,
    challenge: {
      rtq: 1,
      challengeId: c.challengeId,
      capability: c.capability,
      capabilityVersion: c.capabilityVersion,
      inputHash: c.inputHash,
      summary: c.summary as Record<string, unknown>,
      risk: c.risk as RiskLevel,
      policyVersion: c.policyVersion,
      origin: (c.origin as Origin) ?? "unknown",
      expiresAt: c.expiresAt,
      nonce: c.nonce,
    },
  };
}

export function createChallenge(params: {
  capability: string;
  capabilityVersion: number;
  inputHash: string;
  summary: Record<string, unknown>;
  risk: RiskLevel;
  policyVersion: string;
  origin: Origin;
  ttlMs?: number;
}): ApprovalChallenge {
  return {
    rtq: 1,
    challengeId: uuidV4(),
    capability: params.capability,
    capabilityVersion: params.capabilityVersion,
    inputHash: params.inputHash,
    summary: params.summary,
    risk: params.risk,
    policyVersion: params.policyVersion,
    origin: params.origin,
    expiresAt: Date.now() + (params.ttlMs ?? CHALLENGE_TTL_MS),
    nonce: nonce(),
  };
}

/**
 * Sign an approval with the caller-supplied device key (HMAC-SHA256).
 * In production the device key lives in platform secure storage
 * (Keychain / Credential Locker / TPM) and never leaves the device.
 */
export function signDeviceApproval(
  deviceKey: string | Buffer,
  challengeId: string,
  decision: "granted" | "denied",
  keyId: string,
  signedAt = Date.now(),
): DeviceApproval {
  const body: DeviceApprovalBody = { challengeId, decision, keyId, signedAt };
  const signature = hmacSha256Hex(deviceKey, approvalBody(body));
  return { challengeId, decision, keyId, signedAt, signature };
}

/** Verify a device approval signature (constant time). */
export function verifyDeviceApprovalSignature(
  deviceKey: string | Buffer,
  approval: DeviceApproval,
): boolean {
  const expected = hmacSha256Hex(deviceKey, approvalBody(approval));
  return timingSafeEqualHex(approval.signature, expected);
}

export interface ChallengeRegistryOptions {
  ttlMs?: number;
}

interface ChallengeEntry {
  challenge: ApprovalChallenge;
  redeemed: boolean;
}

/**
 * Server-side challenge registry: challenges are single-use and short-lived.
 * A granted approval can only be consumed once and only while the challenge
 * it is bound to is live.
 */
export class ChallengeRegistry {
  private readonly challenges = new Map<string, ChallengeEntry>();
  private readonly ttlMs: number;

  constructor(options: ChallengeRegistryOptions = {}) {
    this.ttlMs = options.ttlMs ?? CHALLENGE_TTL_MS;
  }

  /**
   * Remove expired challenges so the registry does not grow unboundedly
   * (the automatic-path challenge flow never redeems, only expires).
   * Returns the number of entries purged.
   */
  purgeExpired(): number {
    const now = Date.now();
    let purged = 0;
    for (const [id, entry] of this.challenges) {
      if (now > entry.challenge.expiresAt) {
        this.challenges.delete(id);
        purged += 1;
      }
    }
    return purged;
  }

  register(challenge: ApprovalChallenge): void {
    // Opportunistic cleanup: keep the registry bounded without a timer.
    this.purgeExpired();
    this.challenges.set(challenge.challengeId, { challenge, redeemed: false });
  }

  /** Verify a device approval against the registry; marks the challenge redeemed on success. */
  verifyAndRedeem(
    approval: DeviceApproval,
    getDeviceKey: (keyId: string) => string | Buffer | null,
  ):
    { ok: true; challenge: ApprovalChallenge } | { ok: false; reason: string } {
    const entry = this.challenges.get(approval.challengeId);
    if (!entry) return { ok: false, reason: "unknown challenge" };
    const { challenge } = entry;

    if (Date.now() > challenge.expiresAt) {
      this.challenges.delete(approval.challengeId);
      return { ok: false, reason: "challenge expired" };
    }
    if (entry.redeemed) {
      return { ok: false, reason: "challenge already redeemed (replay)" };
    }
    if (approval.decision !== "granted") {
      return {
        ok: false,
        reason: `approval decision is "${approval.decision}"`,
      };
    }
    if (
      approval.signedAt <
      challenge.expiresAt - this.ttlMs - CHALLENGE_SKEW_MS
    ) {
      return { ok: false, reason: "approval predates challenge (replay)" };
    }

    const key = getDeviceKey(approval.keyId);
    if (!key)
      return { ok: false, reason: `unknown device key "${approval.keyId}"` };
    if (!verifyDeviceApprovalSignature(key, approval)) {
      return { ok: false, reason: "approval signature invalid" };
    }

    entry.redeemed = true;
    return { ok: true, challenge };
  }

  peek(challengeId: string): { expiresAt: number; redeemed: boolean } | null {
    const entry = this.challenges.get(challengeId);
    if (!entry) return null;
    return { expiresAt: entry.challenge.expiresAt, redeemed: entry.redeemed };
  }

  revoke(challengeId: string): boolean {
    return this.challenges.delete(challengeId);
  }

  get size(): number {
    return this.challenges.size;
  }
}
