/**
 * Cross-implementation protocol vectors.
 *
 * These vectors are shared with the Dart implementation in `apps/rtq-mobile`.
 * The TypeScript side must parse, re-derive and verify every byte. If the Dart
 * tests pass against the same file, the two implementations agree.
 */
import { readFileSync } from "fs";
import path from "path";
import { describe, expect, it } from "vitest";
import {
  canonicalStringify,
  deviceIdFromPublicKey,
  ed25519Verify,
} from "@rtq/crypto";
import type { JsonWebKey } from "crypto";
import {
  approvalSigningBody,
  challengeSigningBody,
  encodeChallengeV1,
  encodePairingChallengeV1,
  encodePairingResponseV1,
  pairingResponseSigningBody,
  pairingSigningBody,
  parseChallengeV1,
  parsePairingChallengeV1,
  signApprovalV1,
  verifyApprovalSignatureV1,
  verifyHostSignatureV1,
  verifyPairingHostSignatureV1,
  verifyPairingResponseV1,
  type ChallengeV1,
  type PairingChallengeV1,
  type SignedApprovalV1,
  type SignedPairingResponseV1,
} from "@rtq/approval";

const vectorsPath = path.resolve(
  __dirname,
  "../../protocol/rtq-approval-v1.vectors.json",
);
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  canonicalStringifyExamples: Array<{ input: unknown; canonical: string }>;
  keys: Record<string, { publicKeyJwk: JsonWebKey; privateKeyJwk: JsonWebKey }>;
  challenge: {
    unsigned: Record<string, unknown>;
    signed: ChallengeV1;
    signingBody: string;
    hostSignature: string;
    qrPayload: string;
  };
  approvals: Record<
    "granted" | "denied",
    {
      unsigned: Record<string, unknown>;
      signature: string;
      signingBody: string;
      json: string;
    }
  >;
  pairing: {
    unsigned: Record<string, unknown>;
    signed: PairingChallengeV1;
    signingBody: string;
    hostSignature: string;
    qrPayload: string;
    response: {
      unsigned: Record<string, unknown>;
      deviceSignature: string;
      signingBody: string;
      json: string;
    };
  };
};

describe("rtq-approval-v1 shared vectors", () => {
  it("pins canonical JSON serialization", () => {
    for (const example of vectors.canonicalStringifyExamples) {
      expect(canonicalStringify(example.input)).toBe(example.canonical);
    }
  });

  it("re-derives the challenge signing body and host signature", () => {
    const challenge = vectors.challenge.signed;
    const body = challengeSigningBody(vectors.challenge.unsigned as never);
    expect(body).toBe(vectors.challenge.signingBody);
    expect(
      ed25519Verify(
        vectors.keys.host!.publicKeyJwk,
        body,
        vectors.challenge.hostSignature,
      ),
    ).toBe(true);
    expect(verifyHostSignatureV1(challenge)).toBe(true);
  });

  it("round-trips the challenge QR payload", () => {
    expect(vectors.challenge.qrPayload).toBe(
      encodeChallengeV1(vectors.challenge.signed),
    );
    const parsed = parseChallengeV1(vectors.challenge.qrPayload);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value).toEqual(vectors.challenge.signed);
      expect(
        verifyHostSignatureV1(parsed.value, challengeHostPublicKey()),
      ).toBe(true);
    }
  });

  it("verifies the granted approval and its device fingerprint", () => {
    const expected = vectors.approvals.granted;
    const signed = {
      ...(expected.unsigned as object),
      signature: expected.signature,
    } as SignedApprovalV1;
    expect(approvalSigningBody(signed)).toBe(expected.signingBody);
    expect(
      verifyApprovalSignatureV1(signed, vectors.keys.deviceA!.publicKeyJwk),
    ).toBe(true);
    expect(deviceIdFromPublicKey(vectors.keys.deviceA!.publicKeyJwk)).toBe(
      signed.deviceId,
    );
  });

  it("reproduces the granted signature deterministically", () => {
    // Ed25519 is deterministic; the same key + body must give the same bytes.
    const expected = {
      ...(vectors.approvals.granted.unsigned as object),
      signature: vectors.approvals.granted.signature,
    } as SignedApprovalV1;
    const recreated = signApprovalV1({
      challenge: vectors.challenge.signed,
      decision: "granted",
      deviceKeyPair: {
        publicKeyJwk: vectors.keys.deviceA!.publicKeyJwk,
        privateKeyJwk: vectors.keys.deviceA!.privateKeyJwk,
      },
      signedAt: expected.signedAt,
    });
    expect(recreated.signature).toBe(vectors.approvals.granted.signature);
    expect(recreated).toEqual(expected);
  });

  it("verifies the denied approval signed by a different device", () => {
    const expected = vectors.approvals.denied;
    const signed = {
      ...(expected.unsigned as object),
      signature: expected.signature,
    } as SignedApprovalV1;
    expect(approvalSigningBody(signed)).toBe(expected.signingBody);
    expect(
      verifyApprovalSignatureV1(signed, vectors.keys.deviceB!.publicKeyJwk),
    ).toBe(true);
    expect(signed.deviceId).not.toBe(
      vectors.approvals.granted.unsigned.deviceId,
    );
  });

  it("re-derives the pairing challenge and response signatures", () => {
    const pairing = vectors.pairing.signed;
    expect(pairingSigningBody(vectors.pairing.unsigned as never)).toBe(
      vectors.pairing.signingBody,
    );
    expect(verifyPairingHostSignatureV1(pairing)).toBe(true);
    expect(vectors.pairing.qrPayload).toBe(encodePairingChallengeV1(pairing));

    const response = {
      ...(vectors.pairing.response.unsigned as object),
      deviceSignature: vectors.pairing.response.deviceSignature,
    } as SignedPairingResponseV1;
    expect(pairingResponseSigningBody(response)).toBe(
      vectors.pairing.response.signingBody,
    );
    expect(verifyPairingResponseV1(response)).toBe(true);
    expect(vectors.pairing.response.json).toBe(
      encodePairingResponseV1(response),
    );
  });

  it("fails closed when any signed field is tampered with", () => {
    // Risk downgrade: host signature must break.
    const downgraded = {
      ...vectors.challenge.signed,
      risk: "low" as const,
    };
    expect(verifyHostSignatureV1(downgraded)).toBe(false);

    // Approval re-pointed at a different capability.
    const repointed = {
      ...(vectors.approvals.granted.unsigned as object),
      challenge: {
        ...(vectors.approvals.granted.unsigned as { challenge: object })
          .challenge,
        capability: "files.read",
      },
      signature: vectors.approvals.granted.signature,
    } as SignedApprovalV1;
    expect(
      verifyApprovalSignatureV1(repointed, vectors.keys.deviceA!.publicKeyJwk),
    ).toBe(false);

    // Signature transplanted onto a different body.
    const moved = {
      ...(vectors.approvals.granted.unsigned as object),
      signedAt:
        (vectors.approvals.granted.unsigned as { signedAt: number }).signedAt +
        1,
      signature: vectors.approvals.granted.signature,
    } as SignedApprovalV1;
    expect(
      verifyApprovalSignatureV1(moved, vectors.keys.deviceA!.publicKeyJwk),
    ).toBe(false);
  });

  it("rejects a host key that does not match the pinned pairing key", () => {
    const otherPublic = vectors.keys.deviceB!.publicKeyJwk;
    expect(
      verifyHostSignatureV1(vectors.challenge.signed, otherPublic.x as string),
    ).toBe(false);
  });
});

function challengeHostPublicKey(): string {
  return vectors.challenge.signed.hostPublicKey;
}
