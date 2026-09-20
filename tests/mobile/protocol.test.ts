/**
 * Security tests for the `rtq-approval-v1` device protocol.
 *
 * Every test here represents an attack or a failure mode the host must reject.
 * A passing suite is evidence that the host fails closed.
 */
import { describe, expect, it } from "vitest";
import {
  deviceIdFromPublicKey,
  generateEd25519KeyPair,
  strictJsonParse,
  StrictJsonError,
} from "@rtq/crypto";
import {
  CHALLENGE_QR_PREFIX,
  DeviceRegistry,
  DeviceVerificationApprovalV1,
  MobileApprovalVerifier,
  ChallengeStoreV1,
  PairingManager,
  PROTOCOL_ERROR,
  createChallengeV1,
  encodeChallengeV1,
  isSupportedRtqQr,
  parseChallengeV1,
  parsePairingChallengeV1,
  signApprovalV1,
  signPairingResponseV1,
  verifyHostSignatureV1,
  type ChallengeV1,
  type SignedApprovalV1,
} from "@rtq/approval";

const HOST = generateEd25519KeyPair();
const DEVICE = generateEd25519KeyPair();
const OTHER_DEVICE = generateEd25519KeyPair();

const HOST_ID = "rtq-host-01";
const APPLICATION = "RTQ Desktop";
const INPUT_HASH = "a".repeat(64);

let clock = 1_750_000_000_000;

function makeChallenge(
  overrides: Partial<{
    inputHash: string;
    risk: "low" | "medium" | "high" | "critical";
    challengeId: string;
  }> = {},
): ChallengeV1 {
  return createChallengeV1({
    challengeId: overrides.challengeId ?? "ch-1",
    challenge: {
      capability: "files.delete",
      capabilityVersion: 1,
      inputHash: overrides.inputHash ?? INPUT_HASH,
      summary: { action: "Delete file", path: "/w/secret.txt" },
      risk: overrides.risk ?? "high",
      policyVersion: "policy-v3",
      origin: "local",
    },
    host: {
      hostId: HOST_ID,
      application: APPLICATION,
      hostPrivateKey: HOST.privateKeyJwk,
      hostPublicKey: HOST.publicKeyJwk,
    },
    ttlMs: 300_000,
    now: clock,
  });
}

function registeredDevices(): DeviceRegistry {
  const registry = new DeviceRegistry({ now: () => clock });
  registry.register({
    deviceId: deviceIdFromPublicKey(DEVICE.publicKeyJwk),
    publicKeyJwk: DEVICE.publicKeyJwk,
    name: "iPhone",
    status: "authorized",
    registeredAt: clock,
  });
  return registry;
}

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

describe("strict JSON parsing", () => {
  it("rejects duplicate object keys", () => {
    expect(() => strictJsonParse('{"a":1,"a":2}')).toThrow(StrictJsonError);
  });
  it("rejects trailing content and unterminated input", () => {
    expect(() => strictJsonParse('{"a":1} x')).toThrow(StrictJsonError);
    expect(() => strictJsonParse('{"a":1')).toThrow(StrictJsonError);
  });
  it("parses well-formed nested JSON", () => {
    expect(strictJsonParse('{"a":[1,2,{"b":true}]}')).toEqual({
      a: [1, 2, { b: true }],
    });
  });
});

describe("challenge parsing", () => {
  it("round-trips an encoded challenge", () => {
    const challenge = makeChallenge();
    const parsed = parseChallengeV1(encodeChallengeV1(challenge));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.value).toEqual(challenge);
    expect(isSupportedRtqQr(encodeChallengeV1(challenge))).toBe(true);
  });

  it("does not recognize arbitrary QR codes", () => {
    expect(isSupportedRtqQr("https://evil.example/approve")).toBe(false);
    expect(isSupportedRtqQr("rtq://something-else?v=1")).toBe(false);
    expect(parseChallengeV1("https://evil.example/approve").ok).toBe(false);
  });

  it("rejects unsupported protocol and version", () => {
    const challenge = makeChallenge();
    const wrongProtocol = parseChallengeV1(
      CHALLENGE_QR_PREFIX +
        b64url({ ...challenge, protocol: "rtq-approval-v2" }),
    );
    expect(wrongProtocol.ok).toBe(false);
    if (!wrongProtocol.ok) {
      expect(wrongProtocol.code).toBe(PROTOCOL_ERROR.UNSUPPORTED_PROTOCOL);
    }
    const wrongVersion = parseChallengeV1(
      CHALLENGE_QR_PREFIX + b64url({ ...challenge, version: 2 }),
    );
    expect(wrongVersion.ok).toBe(false);
    if (!wrongVersion.ok) {
      expect(wrongVersion.code).toBe(PROTOCOL_ERROR.UNSUPPORTED_VERSION);
    }
  });

  it("rejects a payload with duplicate keys", () => {
    const challenge = makeChallenge();
    const json = JSON.stringify(challenge);
    // Duplicate `risk`: last-wins parsers would see "low", strict parsers reject.
    const duplicated = json.replace(
      '"risk":"high"',
      '"risk":"high","risk":"low"',
    );
    const parsed = parseChallengeV1(
      CHALLENGE_QR_PREFIX + b64urlRaw(duplicated),
    );
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.code).toBe(PROTOCOL_ERROR.DUPLICATE_JSON_KEY);
  });

  it("rejects non-canonical base64url and unknown kinds", () => {
    const padded = parseChallengeV1(CHALLENGE_QR_PREFIX + "eyJhIjoxfQ==");
    expect(padded.ok).toBe(false);
    if (!padded.ok) expect(padded.code).toBe(PROTOCOL_ERROR.MALFORMED_BASE64);

    const unknownKind = parseChallengeV1(
      CHALLENGE_QR_PREFIX + b64url({ ...makeChallenge(), kind: "pairing" }),
    );
    expect(unknownKind.ok).toBe(false);
    if (!unknownKind.ok)
      expect(unknownKind.code).toBe(PROTOCOL_ERROR.UNKNOWN_KIND);
  });

  it("rejects structurally invalid fields", () => {
    const challenge = makeChallenge();
    for (const patch of [
      { inputHash: "not-a-hash" },
      { risk: "apocalyptic" },
      { origin: "elsewhere" },
      { capability: "" },
      { nonce: "short" },
      { hostSignature: "00".repeat(10) },
    ]) {
      const parsed = parseChallengeV1(
        CHALLENGE_QR_PREFIX + b64url({ ...challenge, ...patch }),
      );
      expect(parsed.ok).toBe(false);
    }
  });

  it("rejects a tampered risk even though the envelope parses", () => {
    const challenge = makeChallenge();
    const tampered = { ...challenge, risk: "low" as const };
    const parsed = parseChallengeV1(CHALLENGE_QR_PREFIX + b64url(tampered));
    expect(parsed.ok).toBe(true);
    // Structural parse is not trust: the host signature no longer verifies,
    // so the device rejects the downgraded challenge before showing it.
    if (parsed.ok) {
      expect(verifyHostSignatureV1(parsed.value)).toBe(false);
      expect(verifyHostSignatureV1(challenge)).toBe(true);
    }
  });
});

describe("DeviceRegistry", () => {
  it("refuses a record whose id is not the key fingerprint", () => {
    const registry = new DeviceRegistry();
    expect(() =>
      registry.register({
        deviceId: "f".repeat(64),
        publicKeyJwk: DEVICE.publicKeyJwk,
        name: "spoof",
        status: "authorized",
        registeredAt: clock,
      }),
    ).toThrow(/fingerprint/);
  });

  it("treats revoked and expired devices as unauthorized", () => {
    const registry = registeredDevices();
    const id = deviceIdFromPublicKey(DEVICE.publicKeyJwk);
    expect(registry.isAuthorized(id)).toBe(true);
    registry.revoke(id, "lost phone");
    expect(registry.isAuthorized(id)).toBe(false);
    expect(registry.rejectionFor(id)).toBe(PROTOCOL_ERROR.DEVICE_REVOKED);

    const expiring = new DeviceRegistry({ now: () => clock });
    expiring.register({
      deviceId: id,
      publicKeyJwk: DEVICE.publicKeyJwk,
      name: "old",
      status: "authorized",
      registeredAt: clock,
      expiresAt: clock + 10,
    });
    clock += 100;
    expect(expiring.rejectionFor(id)).toBe(PROTOCOL_ERROR.DEVICE_EXPIRED);
    clock -= 100;
  });
});

describe("pairing", () => {
  function manager(confirm = true) {
    const registry = new DeviceRegistry({ now: () => clock });
    const pairing = new PairingManager({
      hostId: HOST_ID,
      application: APPLICATION,
      hostPrivateKey: HOST.privateKeyJwk,
      hostPublicKey: HOST.publicKeyJwk,
      registry,
      onUserConfirmation: () => confirm,
      now: () => clock,
    });
    return { registry, pairing };
  }

  it("completes pairing with a signed response and registers the device", async () => {
    const { registry, pairing } = manager();
    const created = pairing.createPairingChallenge({ userHint: "build-01" });
    const parsed = parsePairingChallengeV1(created.payload);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const response = signPairingResponseV1({
      pairing: parsed.value,
      deviceName: "iPhone",
      deviceKeyPair: DEVICE,
      signedAt: clock,
    });
    const result = await pairing.completePairing(response);
    expect(result.ok).toBe(true);
    expect(registry.isAuthorized(response.deviceId)).toBe(true);
  });

  it("rejects pairing replay", async () => {
    const { pairing } = manager();
    const created = pairing.createPairingChallenge();
    const parsed = parsePairingChallengeV1(created.payload);
    if (!parsed.ok) throw new Error("bad pairing");
    const response = signPairingResponseV1({
      pairing: parsed.value,
      deviceName: "iPhone",
      deviceKeyPair: DEVICE,
    });
    expect((await pairing.completePairing(response)).ok).toBe(true);
    const replay = await pairing.completePairing(response);
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.code).toBe(PROTOCOL_ERROR.PAIRING_REDEEMED);
  });

  it("rejects an expired pairing challenge", async () => {
    const { pairing } = manager();
    const created = pairing.createPairingChallenge({ ttlMs: 10 });
    const parsed = parsePairingChallengeV1(created.payload);
    if (!parsed.ok) throw new Error("bad pairing");
    const response = signPairingResponseV1({
      pairing: parsed.value,
      deviceName: "iPhone",
      deviceKeyPair: DEVICE,
    });
    clock += 1000;
    const result = await pairing.completePairing(response);
    clock -= 1000;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(PROTOCOL_ERROR.PAIRING_EXPIRED);
  });

  it("rejects a pairing response with a broken device signature", async () => {
    const { pairing } = manager();
    const created = pairing.createPairingChallenge();
    const parsed = parsePairingChallengeV1(created.payload);
    if (!parsed.ok) throw new Error("bad pairing");
    const response = signPairingResponseV1({
      pairing: parsed.value,
      deviceName: "iPhone",
      deviceKeyPair: DEVICE,
    });
    const tampered = { ...response, deviceName: "attacker" };
    const result = await pairing.completePairing(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(PROTOCOL_ERROR.PAIRING_SIGNATURE_INVALID);
    }
  });

  it("fails closed when the host user declines pairing", async () => {
    const { registry, pairing } = manager(false);
    const created = pairing.createPairingChallenge();
    const parsed = parsePairingChallengeV1(created.payload);
    if (!parsed.ok) throw new Error("bad pairing");
    const response = signPairingResponseV1({
      pairing: parsed.value,
      deviceName: "iPhone",
      deviceKeyPair: DEVICE,
    });
    const result = await pairing.completePairing(response);
    expect(result.ok).toBe(false);
    expect(registry.size).toBe(0);
  });
});

describe("MobileApprovalVerifier", () => {
  function setup() {
    const devices = registeredDevices();
    const challenges = new ChallengeStoreV1({
      ttlMs: 300_000,
      now: () => clock,
    });
    const verifier = new MobileApprovalVerifier({
      challenges,
      devices,
      now: () => clock,
    });
    return { devices, challenges, verifier };
  }

  it("accepts a valid approval exactly once", () => {
    const { challenges, verifier } = setup();
    const challenge = makeChallenge();
    challenges.register(challenge);
    const approval = signApprovalV1({
      challenge,
      decision: "granted",
      deviceKeyPair: DEVICE,
      signedAt: clock + 1,
    });
    expect(verifier.verify(approval).ok).toBe(true);
    const replay = verifier.verify(approval);
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.code).toBe(PROTOCOL_ERROR.CHALLENGE_REDEEMED);
  });

  it("rejects an unknown challenge", () => {
    const { verifier } = setup();
    const approval = signApprovalV1({
      challenge: makeChallenge(),
      decision: "granted",
      deviceKeyPair: DEVICE,
    });
    const result = verifier.verify(approval);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(PROTOCOL_ERROR.CHALLENGE_UNKNOWN);
  });

  it("rejects an expired challenge", () => {
    const { challenges, verifier } = setup();
    const challenge = makeChallenge();
    challenges.register(challenge);
    const approval = signApprovalV1({
      challenge,
      decision: "granted",
      deviceKeyPair: DEVICE,
      signedAt: clock,
    });
    clock = challenge.expiresAt + 1;
    const result = verifier.verify(approval);
    clock = 1_750_000_000_000;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(PROTOCOL_ERROR.CHALLENGE_EXPIRED);
  });

  it("rejects devices that are unknown or revoked", () => {
    const { devices, challenges, verifier } = setup();
    const challenge = makeChallenge();
    challenges.register(challenge);

    // Unknown device.
    const unknown = signApprovalV1({
      challenge,
      decision: "granted",
      deviceKeyPair: OTHER_DEVICE,
      signedAt: clock,
    });
    const unknownResult = verifier.verify(unknown);
    expect(unknownResult.ok).toBe(false);
    if (!unknownResult.ok) {
      expect(unknownResult.code).toBe(PROTOCOL_ERROR.DEVICE_UNKNOWN);
    }

    // Revoked device.
    const id = deviceIdFromPublicKey(DEVICE.publicKeyJwk);
    devices.revoke(id, "lost");
    const revoked = signApprovalV1({
      challenge,
      decision: "granted",
      deviceKeyPair: DEVICE,
      signedAt: clock,
    });
    const revokedResult = verifier.verify(revoked);
    expect(revokedResult.ok).toBe(false);
    if (!revokedResult.ok) {
      expect(revokedResult.code).toBe(PROTOCOL_ERROR.DEVICE_REVOKED);
    }
  });

  it("rejects a bad device signature for a registered device", () => {
    const { challenges, verifier } = setup();
    const challenge = makeChallenge();
    challenges.register(challenge);
    const approval = signApprovalV1({
      challenge,
      decision: "granted",
      deviceKeyPair: DEVICE,
      signedAt: clock,
    });
    const tampered: SignedApprovalV1 = {
      ...approval,
      challenge: { ...approval.challenge, capabilityVersion: 2 },
    };
    const result = verifier.verify(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(PROTOCOL_ERROR.DEVICE_SIGNATURE_INVALID);
    }
  });

  it("rejects a validly signed binding for a different operation (binding mismatch)", () => {
    const { challenges, verifier } = setup();
    const stored = makeChallenge({ inputHash: INPUT_HASH });
    const other = makeChallenge({ inputHash: "b".repeat(64) });
    // Same challengeId, different inputHash: signature is valid for `other`,
    // but the host stored `stored` under that id.
    challenges.register(stored);
    const approval = signApprovalV1({
      challenge: other,
      decision: "granted",
      deviceKeyPair: DEVICE,
      signedAt: clock,
    });
    const result = verifier.verify(approval);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(PROTOCOL_ERROR.BINDING_MISMATCH);
  });

  it("rejects a denied decision", () => {
    const { challenges, verifier } = setup();
    const challenge = makeChallenge();
    challenges.register(challenge);
    const approval = signApprovalV1({
      challenge,
      decision: "denied",
      deviceKeyPair: DEVICE,
      signedAt: clock,
    });
    const result = verifier.verify(approval);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(PROTOCOL_ERROR.DECISION_DENIED);
  });

  it("rejects an approval that predates the challenge window", () => {
    const { challenges, verifier } = setup();
    const challenge = makeChallenge();
    challenges.register(challenge);
    const approval = signApprovalV1({
      challenge,
      decision: "granted",
      deviceKeyPair: DEVICE,
      signedAt: clock - 120_000,
    });
    const result = verifier.verify(approval);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe(PROTOCOL_ERROR.CLOCK_SKEW);
  });
});

describe("DeviceVerificationApprovalV1 provider", () => {
  function request() {
    return {
      challengeId: "ch-provider-1",
      capability: "files.delete",
      capabilityVersion: 1,
      inputHash: INPUT_HASH,
      summary: { action: "Delete file" },
      risk: "high" as const,
      origin: "local" as const,
      strategy: "device_verification" as const,
    };
  }

  it("grants only after the device signs the exact presented challenge", async () => {
    const devices = registeredDevices();
    let presented: ChallengeV1 | null = null;
    const provider = new DeviceVerificationApprovalV1({
      hostId: HOST_ID,
      application: APPLICATION,
      hostPrivateKey: HOST.privateKeyJwk,
      hostPublicKey: HOST.publicKeyJwk,
      devices,
      presentChallenge: (_payload, challenge) => {
        presented = challenge;
      },
      awaitApproval: async () => {
        if (!presented) throw new Error("no challenge presented");
        return signApprovalV1({
          challenge: presented,
          decision: "granted",
          deviceKeyPair: DEVICE,
          signedAt: clock,
        });
      },
      now: () => clock,
      timeoutMs: 5000,
    });
    const outcome = await provider.requestApproval(request());
    expect(outcome.decision).toBe("granted");
    if (outcome.decision === "granted") {
      expect(outcome.method).toBe("device_verification");
    }
  });

  it("denies when the device submits a mismatched binding", async () => {
    const devices = registeredDevices();
    const provider = new DeviceVerificationApprovalV1({
      hostId: HOST_ID,
      application: APPLICATION,
      hostPrivateKey: HOST.privateKeyJwk,
      hostPublicKey: HOST.publicKeyJwk,
      devices,
      presentChallenge: () => {},
      awaitApproval: async () =>
        signApprovalV1({
          challenge: makeChallenge({ inputHash: "c".repeat(64) }),
          decision: "granted",
          deviceKeyPair: DEVICE,
          signedAt: clock,
        }),
      now: () => clock,
      timeoutMs: 5000,
    });
    const outcome = await provider.requestApproval(request());
    expect(outcome.decision).toBe("denied");
  });

  it("times out without granting when the device never responds", async () => {
    const devices = registeredDevices();
    const provider = new DeviceVerificationApprovalV1({
      hostId: HOST_ID,
      application: APPLICATION,
      hostPrivateKey: HOST.privateKeyJwk,
      hostPublicKey: HOST.publicKeyJwk,
      devices,
      presentChallenge: () => {},
      awaitApproval: () => new Promise<never>(() => {}),
      now: () => clock,
      timeoutMs: 10,
    });
    const outcome = await provider.requestApproval(request());
    expect(outcome.decision).toBe("timeout");
  });
});

function b64urlRaw(text: string): string {
  return Buffer.from(text, "utf8").toString("base64url");
}
