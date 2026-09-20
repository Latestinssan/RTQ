/**
 * Generates `protocol/rtq-approval-v1.vectors.json`.
 *
 * The vectors are produced by the TypeScript implementation itself, so they
 * cannot drift from it. The Dart implementation consumes the same file and must
 * reproduce byte-identical canonical bodies and signatures. Run with:
 *
 *   RTQ_WRITE_VECTORS=1 npx vitest run tests/protocol/generate-vectors.test.ts
 *
 * (This is a generator, not a test of behaviour; it is skipped by default.)
 */
import { describe, it } from "vitest";
import { writeFileSync, mkdirSync } from "fs";
import path from "path";
import { sha256Hex, canonicalStringify } from "@rtq/crypto";
import {
  approvalSigningBody,
  challengeSigningBody,
  createChallengeV1,
  createPairingChallengeV1,
  encodeChallengeV1,
  encodePairingChallengeV1,
  encodePairingResponseV1,
  pairingResponseSigningBody,
  pairingSigningBody,
  signApprovalV1,
  signPairingResponseV1,
  type ChallengeV1,
  type PairingChallengeV1,
  type SignedApprovalV1,
  type SignedPairingResponseV1,
} from "@rtq/approval";

const HOST_PRIVATE = {
  kty: "OKP",
  crv: "Ed25519",
  x: "xDhAR4IIP4BouF41cOi_LJQJX_YifRdQF1MJ9_LkXqc",
  d: "eDvT4LOxBIdnkXJuHjc2iYUcSCNUeDQpJ-rWw-kC4vo",
};
const HOST_PUBLIC = {
  kty: "OKP",
  crv: "Ed25519",
  x: "xDhAR4IIP4BouF41cOi_LJQJX_YifRdQF1MJ9_LkXqc",
};
const DEVICE_A_PRIVATE = {
  kty: "OKP",
  crv: "Ed25519",
  x: "VI-HBNTuwjVznOo-e83neLjVtc_Vbl-EC3iFIfzE4SA",
  d: "8gpQ-EtnQ0xDGfqA8-EgxP1KWIBYnXx8TAB8j4OD9-4",
};
const DEVICE_A_PUBLIC = {
  kty: "OKP",
  crv: "Ed25519",
  x: "VI-HBNTuwjVznOo-e83neLjVtc_Vbl-EC3iFIfzE4SA",
};
const DEVICE_B_PRIVATE = {
  kty: "OKP",
  crv: "Ed25519",
  x: "fdX7SG_-UUrpIvQfIOQ_HC2reZ_XHPEsmOS3od6TNmE",
  d: "SL7-8vYFwP9ocYS02eWvpoDGjlBZr_PvnSveyaGgsb0",
};
const DEVICE_B_PUBLIC = {
  kty: "OKP",
  crv: "Ed25519",
  x: "fdX7SG_-UUrpIvQfIOQ_HC2reZ_XHPEsmOS3od6TNmE",
};

const FIXED_NOW = 1750000000000;

function unsignedCopy<T extends { hostSignature?: string }>(
  value: T,
): Omit<T, "hostSignature"> {
  const copy = { ...value } as T;
  delete copy.hostSignature;
  return copy as Omit<T, "hostSignature">;
}

describe.skipIf(process.env.RTQ_WRITE_VECTORS !== "1")(
  "generate rtq-approval-v1 vectors",
  () => {
    it("writes the shared vector file", () => {
      const inputHash = sha256Hex(
        canonicalStringify({ path: "/workspace/secret.txt" }),
      );

      const challenge: ChallengeV1 = createChallengeV1({
        challengeId: "11111111-1111-4111-8111-111111111111",
        challenge: {
          capability: "files.delete",
          capabilityVersion: 1,
          inputHash,
          summary: {
            action: "Delete file",
            path: "/workspace/secret.txt",
            reversible: false,
          },
          risk: "high",
          policyVersion: "policy-v3",
          origin: "local",
        },
        host: {
          hostId: "rtq-host-01",
          application: "RTQ Desktop",
          hostPrivateKey: HOST_PRIVATE,
          hostPublicKey: HOST_PUBLIC,
        },
        ttlMs: 300000,
        nonce: "0123456789abcdef0123456789abcdef",
        now: FIXED_NOW,
      });

      const granted: SignedApprovalV1 = signApprovalV1({
        challenge,
        decision: "granted",
        deviceKeyPair: {
          publicKeyJwk: DEVICE_A_PUBLIC,
          privateKeyJwk: DEVICE_A_PRIVATE,
        },
        signedAt: FIXED_NOW + 1000,
      });
      const denied: SignedApprovalV1 = signApprovalV1({
        challenge,
        decision: "denied",
        deviceKeyPair: {
          publicKeyJwk: DEVICE_B_PUBLIC,
          privateKeyJwk: DEVICE_B_PRIVATE,
        },
        signedAt: FIXED_NOW + 1000,
      });

      const pairing: PairingChallengeV1 = createPairingChallengeV1({
        host: {
          hostId: "rtq-host-01",
          application: "RTQ Desktop",
          hostPrivateKey: HOST_PRIVATE,
          hostPublicKey: HOST_PUBLIC,
        },
        pairingId: "22222222-2222-4222-8222-222222222222",
        userHint: "Pair with RTQ Desktop on build-01",
        ttlMs: 120000,
        nonce: "fedcba9876543210fedcba9876543210",
        now: FIXED_NOW,
      });

      const pairingResponse: SignedPairingResponseV1 = signPairingResponseV1({
        pairing,
        deviceName: "Test iPhone",
        deviceKeyPair: {
          publicKeyJwk: DEVICE_A_PUBLIC,
          privateKeyJwk: DEVICE_A_PRIVATE,
        },
        signedAt: FIXED_NOW + 500,
      });

      const vectors = {
        protocol: "rtq-approval-v1",
        version: 1,
        description:
          "Shared cross-implementation test vectors. Keys are TEST-ONLY and public on purpose. Canonical bodies are produced by canonicalStringify (recursively sorted keys, no whitespace).",
        canonicalStringifyExamples: [
          { input: { b: 1, a: 2 }, canonical: '{"a":2,"b":1}' },
          {
            input: { z: [3, { y: true, x: null }], a: "s" },
            canonical: '{"a":"s","z":[3,{"x":null,"y":true}]}',
          },
        ],
        keys: {
          host: { publicKeyJwk: HOST_PUBLIC, privateKeyJwk: HOST_PRIVATE },
          deviceA: {
            publicKeyJwk: DEVICE_A_PUBLIC,
            privateKeyJwk: DEVICE_A_PRIVATE,
          },
          deviceB: {
            publicKeyJwk: DEVICE_B_PUBLIC,
            privateKeyJwk: DEVICE_B_PRIVATE,
          },
        },
        challenge: {
          unsigned: unsignedCopy(challenge),
          signed: challenge,
          signingBody: challengeSigningBody(unsignedCopy(challenge)),
          hostSignature: challenge.hostSignature,
          qrPayload: encodeChallengeV1(challenge),
        },
        approvals: {
          granted: {
            unsigned: {
              protocol: granted.protocol,
              version: granted.version,
              kind: granted.kind,
              challenge: granted.challenge,
              decision: granted.decision,
              deviceId: granted.deviceId,
              signedAt: granted.signedAt,
            },
            signature: granted.signature,
            signingBody: approvalSigningBody(granted),
            json: canonicalStringify(granted),
          },
          denied: {
            unsigned: {
              protocol: denied.protocol,
              version: denied.version,
              kind: denied.kind,
              challenge: denied.challenge,
              decision: denied.decision,
              deviceId: denied.deviceId,
              signedAt: denied.signedAt,
            },
            signature: denied.signature,
            signingBody: approvalSigningBody(denied),
            json: canonicalStringify(denied),
          },
        },
        pairing: {
          unsigned: unsignedCopy(pairing),
          signed: pairing,
          signingBody: pairingSigningBody(unsignedCopy(pairing)),
          hostSignature: pairing.hostSignature,
          qrPayload: encodePairingChallengeV1(pairing),
          response: {
            unsigned: {
              protocol: pairingResponse.protocol,
              version: pairingResponse.version,
              kind: pairingResponse.kind,
              pairingId: pairingResponse.pairingId,
              hostId: pairingResponse.hostId,
              nonce: pairingResponse.nonce,
              deviceId: pairingResponse.deviceId,
              deviceName: pairingResponse.deviceName,
              publicKeyJwk: pairingResponse.publicKeyJwk,
              signedAt: pairingResponse.signedAt,
            },
            deviceSignature: pairingResponse.deviceSignature,
            signingBody: pairingResponseSigningBody(pairingResponse),
            json: encodePairingResponseV1(pairingResponse),
          },
        },
      };

      const outPath = path.resolve(
        __dirname,
        "../../protocol/rtq-approval-v1.vectors.json",
      );
      mkdirSync(path.dirname(outPath), { recursive: true });
      writeFileSync(outPath, `${JSON.stringify(vectors, null, 2)}\n`, "utf8");
    });
  },
);
