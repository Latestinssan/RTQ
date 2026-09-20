import type { ApprovalStrategy, Origin, RiskLevel } from "@rtq/core";

/**
 * The approval abstraction.
 *
 * An approval is CONSENT for a specific operation, distinct from
 * authorization (the entitlement that follows). Strategies map to real
 * enforcement channels:
 *
 *   automatic            — low-risk, policy-sanctioned; no human step.
 *   user_confirmation    — host-provided UI prompt (explicit yes/no).
 *   device_verification  — signed approval from an enrolled device
 *                          (challenge-response protocol).
 *   biometric            — platform biometric challenge (WebAuthn etc.).
 *   qr                   — QR challenge scanned by a mobile verifier that
 *                          has performed local authentication.
 *   custom               — application-defined provider.
 */

export interface ApprovalRequest {
  challengeId: string;
  capability: string;
  capabilityVersion: number;
  /** SHA-256 of the canonicalized input. */
  inputHash: string;
  /** What the human/approver sees. */
  summary: Record<string, unknown>;
  risk: RiskLevel;
  origin: Origin;
  strategy: ApprovalStrategy;
  /** Optional structured proof returned with the approval (e.g. device approval). */
  proofHint?: unknown;
}

export type ApprovalOutcome =
  | { decision: "granted"; method: ApprovalStrategy; proof?: unknown }
  | { decision: "denied"; method: ApprovalStrategy; reason?: string }
  | { decision: "timeout"; method: ApprovalStrategy; reason?: string };

export interface ApprovalProvider {
  readonly strategy: ApprovalStrategy;
  /** Request approval. Must resolve within a bounded time (timeout allowed). */
  requestApproval(request: ApprovalRequest): Promise<ApprovalOutcome>;
}

/** Automatic approval provider: grants without a human step. */
export class AutomaticApproval implements ApprovalProvider {
  readonly strategy: ApprovalStrategy = "automatic";
  async requestApproval(_request: ApprovalRequest): Promise<ApprovalOutcome> {
    return { decision: "granted", method: "automatic" };
  }
}

/** Host-injected user confirmation provider (e.g. an Electron dialog). */
export class UserConfirmationApproval implements ApprovalProvider {
  readonly strategy: ApprovalStrategy = "user_confirmation";

  constructor(
    private readonly prompt: (
      request: ApprovalRequest,
    ) => Promise<boolean> | boolean,
  ) {}

  async requestApproval(request: ApprovalRequest): Promise<ApprovalOutcome> {
    try {
      const granted = await this.prompt(request);
      return granted
        ? { decision: "granted", method: "user_confirmation" }
        : {
            decision: "denied",
            method: "user_confirmation",
            reason: "User declined",
          };
    } catch {
      return {
        decision: "denied",
        method: "user_confirmation",
        reason: "Prompt failed",
      };
    }
  }
}

export interface DeviceVerificationApprovalOptions {
  /** Issue a challenge and return the encoded QR payload for display. */
  issueChallenge: (request: ApprovalRequest) => Promise<string> | string;
  /** Wait for a signed device approval. Must resolve within the challenge TTL. */
  awaitApproval: (
    challengeId: string,
  ) => Promise<{ decision: "granted" | "denied"; proof?: unknown } | null>;
  /** How long to wait before timing out, in ms. */
  timeoutMs?: number;
}

/**
 * Device verification approval: the QR challenge is displayed, the mobile
 * verifier returns a signed approval, and this provider waits for it. If the
 * host receives the approval later (e.g. via a push/websocket), the
 * `awaitApproval` callback resolves it.
 */
export class DeviceVerificationApproval implements ApprovalProvider {
  readonly strategy: ApprovalStrategy = "device_verification";
  private readonly timeoutMs: number;

  constructor(private readonly options: DeviceVerificationApprovalOptions) {
    this.timeoutMs = options.timeoutMs ?? 5 * 60 * 1000;
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalOutcome> {
    const payload = await this.options.issueChallenge(request);
    if (!payload) {
      return {
        decision: "denied",
        method: "device_verification",
        reason: "Challenge could not be issued",
      };
    }
    const deadline = new Promise<{
      decision: "granted" | "denied";
      proof?: unknown;
    } | null>((resolve) => {
      const timer = setTimeout(() => resolve(null), this.timeoutMs);
      this.options
        .awaitApproval(request.challengeId)
        .then((result) => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch(() => {
          clearTimeout(timer);
          resolve(null);
        });
    });
    const result = await deadline;
    if (result === null) {
      return {
        decision: "timeout",
        method: "device_verification",
        reason: "Verification timed out",
      };
    }
    return result.decision === "granted"
      ? {
          decision: "granted",
          method: "device_verification",
          proof: result.proof,
        }
      : {
          decision: "denied",
          method: "device_verification",
          reason: "Device declined",
        };
  }
}

/** Custom provider passthrough. */
export class CustomApproval implements ApprovalProvider {
  readonly strategy: ApprovalStrategy = "custom";
  constructor(
    private readonly handler: (
      request: ApprovalRequest,
    ) => Promise<ApprovalOutcome> | ApprovalOutcome,
  ) {}
  async requestApproval(request: ApprovalRequest): Promise<ApprovalOutcome> {
    return this.handler(request);
  }
}

/** Registry mapping strategies to providers. */
export class ApprovalProviderRegistry {
  private readonly providers = new Map<ApprovalStrategy, ApprovalProvider>();

  register(provider: ApprovalProvider): void {
    this.providers.set(provider.strategy, provider);
  }

  get(strategy: ApprovalStrategy): ApprovalProvider | undefined {
    return this.providers.get(strategy);
  }

  has(strategy: ApprovalStrategy): boolean {
    return this.providers.has(strategy);
  }
}
