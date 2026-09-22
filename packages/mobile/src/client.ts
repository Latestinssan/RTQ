/**
 * A simulated device used for integration tests and examples.
 *
 * It performs exactly the checks the real Flutter client performs before it
 * will sign anything:
 *   1. strict-parse the QR payload;
 *   2. reject anything that is not a supported `rtq-approval-v1` challenge;
 *   3. reject unsupported versions and malformed fields;
 *   4. verify the host's Ed25519 signature (pinned to the paired host key);
 *   5. refuse to sign an expired challenge.
 *
 * It is a test/example helper only. It is not part of the trusted host.
 */

import type { Ed25519KeyPair } from "@rtq/crypto";
import { ensureBiometricAuth } from "./biometric";
  parseChallengeV1,
  parsePairingChallengeV1,
  signApprovalV1,
  signPairingResponseV1,
  verifyHostSignatureV1,
  verifyPairingHostSignatureV1,
  type ChallengeV1,
  type SignedApprovalV1,
  type SignedPairingResponseV1,
} from "@rtq/approval";
import { ensureBiometricAuth } from "./biometric";

export interface SimulatedDeviceOptions {
  keyPair: Ed25519KeyPair;
  name: string;
  /** Public key of the host this device trusts (from pairing). */
  pinnedHostPublicKey?: string;
  now?: () => number;
}

export class SimulatedDevice {
  private readonly options: SimulatedDeviceOptions;

  constructor(options: SimulatedDeviceOptions) {
    this.options = options;
  }

  get name(): string {
    return this.options.name;
  }

  get keyPair(): Ed25519KeyPair {
    return this.options.keyPair;
  }

  /** Validate + parse a challenge, returning the structured value or an error. */
  inspectChallenge(
    payload: string,
  ): { ok: true; challenge: ChallengeV1 } | { ok: false; reason: string } {
    const parsed = parseChallengeV1(payload);
    if (!parsed.ok)
      return { ok: false, reason: `${parsed.code}: ${parsed.reason}` };
    const challenge = parsed.value;
    if (!verifyHostSignatureV1(challenge, this.options.pinnedHostPublicKey)) {
      return {
        ok: false,
        reason: "host signature is invalid or host is not trusted",
      };
    }
    const now = this.options.now ? this.options.now() : Date.now();
    if (now > challenge.expiresAt) {
      return { ok: false, reason: "challenge has expired" };
    }
    return { ok: true, challenge };
  }

  /** Sign an approval for a challenge payload (throws when unverifiable). */
  approve(
    payload: string,
    decision: "granted" | "denied" = "granted",
  ): SignedApprovalV1 {
    const inspected = this.inspectChallenge(payload);
    if (!inspected.ok) throw new Error(inspected.reason);
    return signApprovalV1({
      challenge: inspected.challenge,
      decision,
      deviceKeyPair: this.options.keyPair,
      signedAt: this.options.now ? this.options.now() : undefined,
    });
  }

    /**
   * Approve with biometric check (awaitable). Returns a SignedApprovalV1 after the user authenticates.
   */
  async approveWithBiometric(
    payload: string,
    decision: "granted" | "denied" = "granted",
  ): Promise<SignedApprovalV1> {
    await ensureBiometricAuth();
    return this.approve(payload, decision);
  }


  respondToPairing(payload: string): SignedPairingResponseV1 {
    const parsed = parsePairingChallengeV1(payload);
    if (!parsed.ok) {
      throw new Error(`${parsed.code}: ${parsed.reason}`);
    }
    const pairing = parsed.value;
    if (
      !verifyPairingHostSignatureV1(pairing, this.options.pinnedHostPublicKey)
    ) {
      throw new Error(
        "pairing host signature is invalid or host is not trusted",
      );
    }
    return signPairingResponseV1({
      pairing,
      deviceName: this.options.name,
      deviceKeyPair: this.options.keyPair,
      signedAt: this.options.now ? this.options.now() : undefined,
    });
  }
}
