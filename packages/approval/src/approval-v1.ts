/**
 * Host-side verification of `rtq-approval-v1` approvals.
 *
 * The device signature alone proves *someone with the private key* signed
 * something. It does not prove the approval is for the operation the host is
 * about to perform, that the device is allowed to approve, or that this is the
 * first time the approval is used. This module performs the full check:
 *
 *   1. the challenge is known to the host and not yet redeemed (single-use);
 *   2. the challenge is live (expiry + clock skew);
 *   3. the device is registered, authorized, unexpired and not revoked;
 *   4. the Ed25519 signature verifies and `deviceId` is the key fingerprint;
 *   5. every security-critical binding matches the host's pending challenge;
 *   6. the decision is `granted`.
 *
 * Any failure is a DENY. Nothing here "best-effort" accepts.
 */

import type { JsonWebKey } from "crypto";
import { RISK_LEVELS } from "@rtq/core";
import {
  CLOCK_SKEW_MS_V1,
  RTQ_APPROVAL_PROTOCOL,
  RTQ_APPROVAL_PROTOCOL_VERSION,
  verifyApprovalSignatureV1,
  type ChallengeV1,
  type SignedApprovalV1,
} from "./protocol";
import { DeviceRegistry } from "./device";
import { PROTOCOL_ERROR, type ProtocolErrorCode } from "./errors";

export interface ChallengeStoreOptions {
  ttlMs?: number;
  onAudit?: (event: string, detail: Record<string, unknown>) => void;
  now?: () => number;
}

interface StoredChallenge {
  challenge: ChallengeV1;
  redeemed: boolean;
}

/**
 * Host-side store of challenges it has issued. Single-use: redeeming marks the
 * challenge consumed, so a captured approval cannot be replayed.
 */
export class ChallengeStoreV1 {
  private readonly challenges = new Map<string, StoredChallenge>();
  private readonly ttlMs: number;
  private readonly onAudit?: ChallengeStoreOptions["onAudit"];
  private readonly now: () => number;

  constructor(options: ChallengeStoreOptions = {}) {
    this.ttlMs = options.ttlMs ?? 5 * 60 * 1000;
    this.onAudit = options.onAudit;
    this.now = options.now ?? (() => Date.now());
  }

  register(challenge: ChallengeV1): void {
    this.purgeExpired();
    this.challenges.set(challenge.challengeId, { challenge, redeemed: false });
    this.onAudit?.("CHALLENGE_ISSUED", {
      challengeId: challenge.challengeId,
      capability: challenge.capability,
      risk: challenge.risk,
    });
  }

  peek(challengeId: string): { expiresAt: number; redeemed: boolean } | null {
    const entry = this.challenges.get(challengeId);
    if (!entry) return null;
    return { expiresAt: entry.challenge.expiresAt, redeemed: entry.redeemed };
  }

  revoke(challengeId: string): boolean {
    const removed = this.challenges.delete(challengeId);
    if (removed) this.onAudit?.("CHALLENGE_REVOKED", { challengeId });
    return removed;
  }

  purgeExpired(): number {
    const now = this.now();
    let purged = 0;
    for (const [id, entry] of this.challenges) {
      if (now > entry.challenge.expiresAt) {
        this.challenges.delete(id);
        purged += 1;
      }
    }
    return purged;
  }

  get size(): number {
    return this.challenges.size;
  }

  /** Challenge lifetime, exposed so the verifier can bound `signedAt`. */
  get ttl(): number {
    return this.ttlMs;
  }

  /** @internal used by the verifier. */
  take(challengeId: string): StoredChallenge | null {
    return this.challenges.get(challengeId) ?? null;
  }
}

export type ApprovalVerifyResult =
  | { ok: true; challenge: ChallengeV1 }
  | { ok: false; code: ProtocolErrorCode; reason: string };

export interface MobileApprovalVerifierOptions {
  challenges: ChallengeStoreV1;
  devices: DeviceRegistry;
  /** Max accepted clock skew for `signedAt`, default 60s. */
  clockSkewMs?: number;
  onAudit?: (event: string, detail: Record<string, unknown>) => void;
  now?: () => number;
}

export class MobileApprovalVerifier {
  private readonly challenges: ChallengeStoreV1;
  private readonly devices: DeviceRegistry;
  private readonly clockSkewMs: number;
  private readonly onAudit?: MobileApprovalVerifierOptions["onAudit"];
  private readonly now: () => number;

  constructor(options: MobileApprovalVerifierOptions) {
    this.challenges = options.challenges;
    this.devices = options.devices;
    this.clockSkewMs = options.clockSkewMs ?? CLOCK_SKEW_MS_V1;
    this.onAudit = options.onAudit;
    this.now = options.now ?? (() => Date.now());
  }

  private reject(
    code: ProtocolErrorCode,
    reason: string,
  ): ApprovalVerifyResult {
    this.onAudit?.("APPROVAL_REJECTED", { code, reason });
    return { ok: false, code, reason };
  }

  /**
   * Verify a signed approval against host state. On success the challenge is
   * consumed (single-use) before returning.
   */
  verify(approval: SignedApprovalV1): ApprovalVerifyResult {
    if (
      approval.protocol !== RTQ_APPROVAL_PROTOCOL ||
      approval.version !== RTQ_APPROVAL_PROTOCOL_VERSION ||
      approval.kind !== "approval"
    ) {
      return this.reject(
        PROTOCOL_ERROR.UNSUPPORTED_PROTOCOL,
        "approval protocol/version/kind is not supported",
      );
    }
    const entry = this.challenges.take(approval.challenge.challengeId);
    if (!entry) {
      return this.reject(
        PROTOCOL_ERROR.CHALLENGE_UNKNOWN,
        "no pending challenge for this approval",
      );
    }
    const { challenge } = entry;
    const now = this.now();

    if (entry.redeemed) {
      return this.reject(
        PROTOCOL_ERROR.CHALLENGE_REDEEMED,
        "challenge already redeemed (replay)",
      );
    }
    if (now > challenge.expiresAt) {
      this.challenges.revoke(challenge.challengeId);
      return this.reject(PROTOCOL_ERROR.CHALLENGE_EXPIRED, "challenge expired");
    }
    if (
      approval.signedAt <
      challenge.expiresAt - this.challenges.ttl - this.clockSkewMs
    ) {
      return this.reject(
        PROTOCOL_ERROR.CLOCK_SKEW,
        "approval predates the challenge window",
      );
    }

    // Device authorization, checked before signature work to keep the failure
    // modes distinct and the audit trail explicit.
    const rejection = this.devices.rejectionFor(approval.deviceId);
    if (rejection) {
      return this.reject(rejection, `device rejected: ${rejection}`);
    }
    const publicKey: JsonWebKey | null = this.devices.getPublicKey(
      approval.deviceId,
    );
    if (!publicKey) {
      return this.reject(
        PROTOCOL_ERROR.DEVICE_UNKNOWN,
        "device public key is not registered",
      );
    }
    if (!verifyApprovalSignatureV1(approval, publicKey)) {
      return this.reject(
        PROTOCOL_ERROR.DEVICE_SIGNATURE_INVALID,
        "device signature is invalid",
      );
    }

    if (approval.decision !== "granted") {
      return this.reject(
        PROTOCOL_ERROR.DECISION_DENIED,
        `device decision was "${approval.decision}"`,
      );
    }

    const mismatch = bindingMismatch(challenge, approval.challenge);
    if (mismatch) {
      return this.reject(PROTOCOL_ERROR.BINDING_MISMATCH, mismatch);
    }

    entry.redeemed = true;
    this.onAudit?.("APPROVAL_VERIFIED", {
      challengeId: challenge.challengeId,
      deviceId: approval.deviceId,
      capability: challenge.capability,
    });
    return { ok: true, challenge };
  }
}

/** Compare the signed binding against the host's authoritative challenge. */
function bindingMismatch(
  expected: ChallengeV1,
  actual: SignedApprovalV1["challenge"],
): string | null {
  const fields: Array<[string, unknown, unknown]> = [
    ["challengeId", expected.challengeId, actual.challengeId],
    ["capability", expected.capability, actual.capability],
    ["capabilityVersion", expected.capabilityVersion, actual.capabilityVersion],
    ["inputHash", expected.inputHash, actual.inputHash],
    ["risk", expected.risk, actual.risk],
    ["origin", expected.origin, actual.origin],
    ["application", expected.application, actual.application],
    ["hostId", expected.hostId, actual.hostId],
    ["policyVersion", expected.policyVersion, actual.policyVersion],
    ["expiresAt", expected.expiresAt, actual.expiresAt],
    ["nonce", expected.nonce, actual.nonce],
  ];
  for (const [name, want, got] of fields) {
    if (want !== got) {
      return `binding mismatch on "${name}"`;
    }
  }
  // Defensive: reject an unknown risk value even if it happens to equal nothing.
  if (!(RISK_LEVELS as readonly string[]).includes(actual.risk)) {
    return 'binding mismatch on "risk"';
  }
  return null;
}
