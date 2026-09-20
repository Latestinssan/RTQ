/**
 * Approval provider adapter for `rtq-approval-v1`.
 *
 * RTQ's `ApprovalProvider` interface is the host-side extension point for
 * interactive approval (see `providers.ts`). This adapter plugs the v1
 * challenge/approval protocol into that seam:
 *
 *   - it issues a host-signed v1 challenge bound to the exact `ApprovalRequest`;
 *   - it hands the challenge QR to the host UI via `presentChallenge`;
 *   - it waits for the device's signed approval (with a hard timeout);
 *   - it runs the full `MobileApprovalVerifier` check before granting.
 *
 * A timeout, a malformed approval, an unknown/revoked device, a replay, or a
 * binding mismatch all yield a denial — never a grant. This keeps the
 * "fail closed" guarantee in one place instead of trusting the transport.
 */

import type { ApprovalProvider, ApprovalRequest } from "./providers";
import type { ApprovalStrategy } from "@rtq/core";
import type { JsonWebKey } from "crypto";
import { ed25519Sign } from "@rtq/crypto";
import { ChallengeStoreV1, MobileApprovalVerifier } from "./approval-v1";
import { DeviceRegistry } from "./device";
import {
  CHALLENGE_TTL_MS_V1,
  createChallengeV1,
  encodeChallengeV1,
  type ChallengeV1,
  type SignedApprovalV1,
} from "./protocol";

export interface DeviceVerificationApprovalV1Options {
  hostId: string;
  application: string;
  hostPrivateKey: Parameters<typeof ed25519Sign>[0];
  hostPublicKey: JsonWebKey;
  devices: DeviceRegistry;
  /**
   * Deliver the QR payload (and the structured challenge) to the host UI.
   * The mobile app scans this; the host MUST NOT create the approval itself.
   */
  presentChallenge: (
    payload: string,
    challenge: ChallengeV1,
  ) => Promise<void> | void;
  /**
   * Wait for the device to submit a signed approval for `challengeId`.
   * Resolve with `null` when the host gives up (timeout / cancellation).
   */
  awaitApproval: (challengeId: string) => Promise<SignedApprovalV1 | null>;
  onAudit?: (event: string, detail: Record<string, unknown>) => void;
  /** Challenge lifetime, default 5 minutes. */
  ttlMs?: number;
  /** Maximum wait for the device, default 5 minutes. */
  timeoutMs?: number;
  now?: () => number;
}

export class DeviceVerificationApprovalV1 implements ApprovalProvider {
  readonly strategy: ApprovalStrategy;
  private readonly store: ChallengeStoreV1;
  private readonly verifier: MobileApprovalVerifier;
  private readonly timeoutMs: number;
  private readonly now: () => number;

  constructor(
    private readonly options: DeviceVerificationApprovalV1Options,
    strategy: ApprovalStrategy = "device_verification",
  ) {
    this.strategy = strategy;
    this.now = options.now ?? (() => Date.now());
    const ttlMs = options.ttlMs ?? CHALLENGE_TTL_MS_V1;
    this.store = new ChallengeStoreV1({ ttlMs, now: this.now });
    this.verifier = new MobileApprovalVerifier({
      challenges: this.store,
      devices: options.devices,
      onAudit: options.onAudit,
      now: this.now,
    });
    this.timeoutMs = options.timeoutMs ?? ttlMs;
  }

  /** The host-side challenge store (exposed for revocation/debug tooling). */
  get challenges(): ChallengeStoreV1 {
    return this.store;
  }

  async requestApproval(request: ApprovalRequest) {
    const challenge = createChallengeV1({
      challengeId: request.challengeId,
      challenge: {
        capability: request.capability,
        capabilityVersion: request.capabilityVersion,
        inputHash: request.inputHash,
        summary: request.summary,
        risk: request.risk,
        policyVersion: "live",
        origin: request.origin,
      },
      host: {
        hostId: this.options.hostId,
        application: this.options.application,
        hostPrivateKey: this.options.hostPrivateKey,
        hostPublicKey: this.options.hostPublicKey,
      },
      ttlMs: this.options.ttlMs ?? CHALLENGE_TTL_MS_V1,
      now: this.now(),
    });
    this.store.register(challenge);
    const payload = encodeChallengeV1(challenge);
    await this.options.presentChallenge(payload, challenge);

    const deadline = new Promise<null>((resolve) => {
      const timer = setTimeout(() => resolve(null), this.timeoutMs);
      if (typeof timer.unref === "function") timer.unref();
    });
    const received = await Promise.race([
      this.options.awaitApproval(challenge.challengeId),
      deadline,
    ]);
    if (received === null) {
      this.options.onAudit?.("APPROVAL_TIMEOUT", {
        challengeId: challenge.challengeId,
      });
      return {
        decision: "timeout" as const,
        method: this.strategy,
        reason: "Verification timed out",
      };
    }
    const verified = this.verifier.verify(received);
    if (!verified.ok) {
      this.options.onAudit?.("APPROVAL_REJECTED", {
        challengeId: challenge.challengeId,
        code: verified.code,
      });
      return {
        decision: "denied" as const,
        method: this.strategy,
        reason: verified.reason,
      };
    }
    return {
      decision: "granted" as const,
      method: this.strategy,
      proof: { type: "device_approval_v1", approval: received },
    };
  }
}
