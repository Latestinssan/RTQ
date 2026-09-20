/**
 * Host-side mobile approval service.
 *
 * This is the integration seam between RTQ's pipeline and the
 * `rtq-approval-v1` protocol. It implements RTQ's `ApprovalProvider` so it can
 * be handed to `createRTQ({ approvalProviders: [...] })`, and it exposes the
 * pairing and approval-submission operations that the HTTP transport (or any
 * other transport) calls.
 *
 * Trust model: the transport is NOT trusted. A challenge is only accepted if it
 * carries a valid host signature, and an approval is only accepted if its
 * device signature verifies AND every binding matches the host's pending
 * challenge AND the device is authorized. A compromised or spoofed transport
 * can therefore delay or drop messages, but cannot manufacture consent.
 */

import type { JsonWebKey } from "crypto";
import type { ApprovalStrategy } from "@rtq/core";
import { ed25519Sign } from "@rtq/crypto";
import {
  ChallengeStoreV1,
  DeviceRegistry,
  MobileApprovalVerifier,
  PairingManager,
  createChallengeV1,
  encodeChallengeV1,
  parsePairingResponseV1,
  parseSignedApprovalV1,
  type ChallengeV1,
  type CreatedPairing,
  type ProtocolErrorCode,
  type SignedApprovalV1,
} from "@rtq/approval";
import type {
  ApprovalOutcome,
  ApprovalProvider,
  ApprovalRequest,
} from "@rtq/approval";
import { CHALLENGE_TTL_MS_V1, PAIRING_TTL_MS_V1 } from "@rtq/approval";

export interface MobileApprovalServiceOptions {
  hostId: string;
  application: string;
  hostPrivateKey: Parameters<typeof ed25519Sign>[0];
  hostPublicKey: JsonWebKey;
  devices?: DeviceRegistry;
  strategy?: ApprovalStrategy;
  /** Challenge lifetime, default 5 minutes. */
  ttlMs?: number;
  /** How long `requestApproval` waits for the device, default = ttl. */
  timeoutMs?: number;
  pairingTtlMs?: number;
  onAudit?: (event: string, detail: Record<string, unknown>) => void;
  now?: () => number;
  /**
   * Called with the QR payload the host UI must display. The URI encodes the
   * signed challenge; it contains no secret and no approval.
   */
  onPresentChallenge?: (payload: string, challenge: ChallengeV1) => void;
}

export type SubmitApprovalResult =
  | { ok: true; challengeId: string; capability: string; deviceId: string }
  | { ok: false; code: ProtocolErrorCode; reason: string };

interface Waiter {
  resolve: (result: WaiterResult) => void;
}

type WaiterResult =
  | { ok: true; approval: SignedApprovalV1; challenge: ChallengeV1 }
  | { ok: false; code: ProtocolErrorCode; reason: string };

export class MobileApprovalService implements ApprovalProvider {
  readonly strategy: ApprovalStrategy;
  readonly devices: DeviceRegistry;
  readonly challenges: ChallengeStoreV1;
  readonly pairing: PairingManager;
  readonly verifier: MobileApprovalVerifier;

  private readonly options: MobileApprovalServiceOptions;
  private readonly waiters = new Map<string, Waiter>();
  private readonly timeoutMs: number;
  private readonly ttlMs: number;

  constructor(options: MobileApprovalServiceOptions) {
    this.options = options;
    this.strategy = options.strategy ?? "device_verification";
    this.ttlMs = options.ttlMs ?? CHALLENGE_TTL_MS_V1;
    this.timeoutMs = options.timeoutMs ?? this.ttlMs;
    this.devices =
      options.devices ??
      new DeviceRegistry({
        onAudit: options.onAudit,
        now: options.now,
      });
    this.challenges = new ChallengeStoreV1({
      ttlMs: this.ttlMs,
      onAudit: options.onAudit,
      now: options.now,
    });
    this.verifier = new MobileApprovalVerifier({
      challenges: this.challenges,
      devices: this.devices,
      onAudit: options.onAudit,
      now: options.now,
    });
    this.pairing = new PairingManager({
      hostId: options.hostId,
      application: options.application,
      hostPrivateKey: options.hostPrivateKey,
      hostPublicKey: options.hostPublicKey,
      registry: this.devices,
      ttlMs: options.pairingTtlMs ?? PAIRING_TTL_MS_V1,
      onAudit: options.onAudit,
      now: options.now,
    });
  }

  // -------------------------------------------------------------------------
  // ApprovalProvider integration
  // -------------------------------------------------------------------------

  async requestApproval(request: ApprovalRequest): Promise<ApprovalOutcome> {
    const challenge = this.createChallengeFor(request);
    const payload = encodeChallengeV1(challenge);
    this.options.onPresentChallenge?.(payload, challenge);
    const result = await this.waitFor(challenge.challengeId, challenge);
    if (result === null) {
      this.options.onAudit?.("APPROVAL_TIMEOUT", {
        challengeId: challenge.challengeId,
      });
      return {
        decision: "timeout",
        method: this.strategy,
        reason: "Verification timed out",
      };
    }
    if (!result.ok) {
      return {
        decision: "denied",
        method: this.strategy,
        reason: result.reason,
      };
    }
    return {
      decision: "granted",
      method: this.strategy,
      proof: { type: "device_approval_v1", approval: result.approval },
    };
  }

  /** Create + register a host-signed challenge (no waiting). */
  createChallengeFor(request: ApprovalRequest): ChallengeV1 {
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
      ttlMs: this.ttlMs,
      now: this.options.now ? this.options.now() : undefined,
    });
    this.challenges.register(challenge);
    return challenge;
  }

  /** QR payload for an already-created challenge. */
  payloadFor(challenge: ChallengeV1): string {
    return encodeChallengeV1(challenge);
  }

  /** Device-facing: submit a signed approval (raw JSON text). */
  submitApproval(text: string): SubmitApprovalResult {
    const parsed = parseSignedApprovalV1(text);
    if (!parsed.ok) {
      return { ok: false, code: parsed.code, reason: parsed.reason };
    }
    const approval = parsed.value;
    const result = this.verifier.verify(approval);
    const waiter = this.waiters.get(approval.challenge.challengeId);
    if (waiter) {
      this.waiters.delete(approval.challenge.challengeId);
      waiter.resolve(
        result.ok
          ? { ok: true, approval, challenge: result.challenge }
          : { ok: false, code: result.code, reason: result.reason },
      );
    }
    if (!result.ok) {
      return { ok: false, code: result.code, reason: result.reason };
    }
    return {
      ok: true,
      challengeId: result.challenge.challengeId,
      capability: result.challenge.capability,
      deviceId: approval.deviceId,
    };
  }

  // -------------------------------------------------------------------------
  // Pairing
  // -------------------------------------------------------------------------

  startPairing(params: { userHint?: string } = {}): CreatedPairing {
    return this.pairing.createPairingChallenge(params);
  }

  completePairingText(
    text: string,
    options: { deviceName?: string; platform?: string } = {},
  ) {
    const parsed = parsePairingResponseV1(text);
    if (!parsed.ok) {
      return Promise.resolve({
        ok: false as const,
        code: parsed.code,
        reason: parsed.reason,
      });
    }
    return this.pairing.completePairing(parsed.value, options);
  }

  revokeDevice(deviceId: string, reason: string): boolean {
    return this.devices.revoke(deviceId, reason);
  }

  listDevices() {
    return this.devices.list();
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private waitFor(
    challengeId: string,
    challenge: ChallengeV1,
  ): Promise<WaiterResult | null> {
    return new Promise<WaiterResult | null>((resolve) => {
      const timer = setTimeout(() => {
        this.waiters.delete(challengeId);
        resolve(null);
      }, this.timeoutMs);
      if (typeof timer.unref === "function") timer.unref();
      this.waiters.set(challengeId, {
        resolve: (result) => {
          clearTimeout(timer);
          resolve(result);
        },
      });
      // Guard against a challenge that was already redeemed/registered oddly.
      if (!this.challenges.peek(challengeId)) {
        this.challenges.register(challenge);
      }
    });
  }
}
