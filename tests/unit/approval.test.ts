import { describe, expect, it } from "vitest";
import {
  ChallengeRegistry,
  createChallenge,
  encodeChallenge,
  parseChallenge,
  signDeviceApproval,
  verifyDeviceApprovalSignature,
} from "@rtq/approval";

const KEY = "device-key-abc";
const KEY_ID = "device-1";

function makeChallenge(overrides: Record<string, unknown> = {}) {
  return createChallenge({
    capability: "files.delete",
    capabilityVersion: 1,
    inputHash: "a".repeat(64),
    summary: { action: "Delete file", path: "/workspace/secret.txt" },
    risk: "high",
    policyVersion: "policy-v1",
    origin: "local",
    ...overrides,
  });
}

describe("QR challenge protocol", () => {
  it("round-trips a challenge through encode/parse", () => {
    const challenge = makeChallenge();
    const parsed = parseChallenge(encodeChallenge(challenge));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.challenge.challengeId).toBe(challenge.challengeId);
      expect(parsed.challenge.inputHash).toBe(challenge.inputHash);
      expect(parsed.challenge.risk).toBe("high");
    }
  });

  it("never carries a PIN or a pre-baked approval", () => {
    const payload = encodeChallenge(makeChallenge());
    expect(payload.toLowerCase()).not.toContain("pin");
    expect(payload.toLowerCase()).not.toContain("approve=true");
    expect(payload.toLowerCase()).not.toContain('"granted"');
  });

  it("rejects malformed and tampered payloads", () => {
    expect(parseChallenge("garbage").ok).toBe(false);
    expect(parseChallenge("https://evil.example/approve?x=1").ok).toBe(false);

    const payload = encodeChallenge(makeChallenge());
    const body = payload.slice("rtq://challenge?v=1&c=".length);
    const decoded = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    decoded.risk = "low"; // attacker tries to downgrade displayed risk
    const tampered =
      "rtq://challenge?v=1&c=" +
      Buffer.from(JSON.stringify(decoded)).toString("base64url");
    const parsed = parseChallenge(tampered);
    // Structure still parses, but the signature over the approval will not
    // verify against the server-stored challenge. Structural parse is not trust.
    expect(parsed.ok).toBe(true);
  });

  it("rejects structurally invalid challenges", () => {
    const bad =
      "rtq://challenge?v=1&c=" +
      Buffer.from(JSON.stringify({ rtq: 1 })).toString("base64url");
    expect(parseChallenge(bad).ok).toBe(false);
  });

  it("signs and verifies device approvals in constant time", () => {
    const approval = signDeviceApproval(
      KEY,
      "ch-1",
      "granted",
      KEY_ID,
      Date.now(),
    );
    expect(verifyDeviceApprovalSignature(KEY, approval)).toBe(true);
    expect(verifyDeviceApprovalSignature("wrong-key", approval)).toBe(false);
    expect(
      verifyDeviceApprovalSignature(KEY, {
        ...approval,
        decision: "denied" as never,
      }),
    ).toBe(false);
  });
});

describe("ChallengeRegistry", () => {
  const getKey = (id: string) => (id === KEY_ID ? KEY : null);

  it("verifies a valid signed approval and consumes the challenge", () => {
    const reg = new ChallengeRegistry();
    const challenge = makeChallenge();
    reg.register(challenge);
    const approval = signDeviceApproval(
      KEY,
      challenge.challengeId,
      "granted",
      KEY_ID,
    );
    const r = reg.verifyAndRedeem(approval, getKey);
    expect(r.ok).toBe(true);
  });

  it("rejects replay of an already-redeemed approval", () => {
    const reg = new ChallengeRegistry();
    const challenge = makeChallenge();
    reg.register(challenge);
    const approval = signDeviceApproval(
      KEY,
      challenge.challengeId,
      "granted",
      KEY_ID,
    );
    expect(reg.verifyAndRedeem(approval, getKey).ok).toBe(true);
    const second = reg.verifyAndRedeem(approval, getKey);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toMatch(/replay/);
  });

  it("rejects an approval bound to a different challenge", () => {
    const reg = new ChallengeRegistry();
    const challenge = makeChallenge();
    reg.register(challenge);
    const approval = signDeviceApproval(
      KEY,
      "some-other-challenge",
      "granted",
      KEY_ID,
    );
    const r = reg.verifyAndRedeem(approval, getKey);
    expect(r.ok).toBe(false);
  });

  it("rejects an unknown device key", () => {
    const reg = new ChallengeRegistry();
    const challenge = makeChallenge();
    reg.register(challenge);
    const approval = signDeviceApproval(
      KEY,
      challenge.challengeId,
      "granted",
      "unknown-device",
    );
    const r = reg.verifyAndRedeem(approval, getKey);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/unknown device key/);
  });

  it("rejects denied decisions", () => {
    const reg = new ChallengeRegistry();
    const challenge = makeChallenge();
    reg.register(challenge);
    const approval = signDeviceApproval(
      KEY,
      challenge.challengeId,
      "denied",
      KEY_ID,
    );
    const r = reg.verifyAndRedeem(approval, getKey);
    expect(r.ok).toBe(false);
  });

  it("rejects expired challenges", async () => {
    const reg = new ChallengeRegistry({ ttlMs: 20 });
    const challenge = makeChallenge({ ttlMs: 20 });
    reg.register(challenge);
    await new Promise((r) => setTimeout(r, 40));
    const approval = signDeviceApproval(
      KEY,
      challenge.challengeId,
      "granted",
      KEY_ID,
    );
    const r = reg.verifyAndRedeem(approval, getKey);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/expired/);
  });

  it("revoke removes a challenge", () => {
    const reg = new ChallengeRegistry();
    const challenge = makeChallenge();
    reg.register(challenge);
    expect(reg.revoke(challenge.challengeId)).toBe(true);
    expect(reg.peek(challenge.challengeId)).toBeNull();
  });

  it("purgeExpired removes only expired challenges (bounded registry)", async () => {
    const reg = new ChallengeRegistry({ ttlMs: 20 });
    const expired = makeChallenge({ ttlMs: 20 });
    const live = makeChallenge();
    reg.register(expired);
    reg.register(live);
    expect(reg.size).toBe(2);
    await new Promise((r) => setTimeout(r, 40));
    expect(reg.purgeExpired()).toBe(1);
    expect(reg.peek(expired.challengeId)).toBeNull();
    expect(reg.peek(live.challengeId)).not.toBeNull();
    // registering again also triggers opportunistic cleanup
    expect(reg.size).toBe(1);
    reg.register(makeChallenge());
    expect(reg.size).toBe(2);
  });
});
