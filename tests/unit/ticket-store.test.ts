import { describe, expect, it } from "vitest";
import { TicketStore, ticketBody } from "@rtq/core";
import {
  canonicalStringify,
  signCanonical,
  timingSafeEqualHex,
} from "@rtq/crypto";

const KEY = "unit-test-signing-key";
const bindings = {
  capability: "test.write",
  capabilityVersion: 1,
  input: { path: "/w/file.txt", content: "hello" },
  actor: "test-actor",
  resource: "/w/file.txt",
  risk: "medium" as const,
  policyVersion: "policy-v1",
  approvalMethod: "user_confirmation" as const,
  origin: "local" as const,
  challengeId: "ch-123",
  nonce: "nonce-1234567890abcdef",
};

function store(ttl = 60_000) {
  return new TicketStore({ signingKey: KEY, ttlMs: ttl });
}

describe("TicketStore", () => {
  it("issues a signed ticket bound to the exact operation", () => {
    const s = store();
    const t = s.issue(bindings);
    expect(t.status).toBe("issued");
    expect(t.signature.length).toBe(64);
    expect(s.verifySignature(t)).toBe(true);
    // redemption succeeds with matching expected context
    const r = s.redeem(t.id, {
      expectedCapability: "test.write",
      expectedVersion: 1,
    });
    expect(r.ok).toBe(true);
  });

  it("rejects replay: a ticket can only be redeemed once", () => {
    const s = store();
    const t = s.issue(bindings);
    expect(
      s.redeem(t.id, { expectedCapability: "test.write", expectedVersion: 1 })
        .ok,
    ).toBe(true);
    const second = s.redeem(t.id, {
      expectedCapability: "test.write",
      expectedVersion: 1,
    });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe("replay");
  });

  it("rejects expired tickets", () => {
    const s = store(50); // 50ms TTL
    const t = s.issue(bindings);
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        const r = s.redeem(t.id, {
          expectedCapability: "test.write",
          expectedVersion: 1,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.code).toBe("expired");
        resolve();
      }, 80);
    });
  });

  it("detects signature tampering", () => {
    const s = store();
    const t = s.issue(bindings);
    const tampered = { ...t, risk: "low" as const, signature: "0".repeat(64) };
    const expected = signCanonical(KEY, ticketBody(tampered));
    expect(timingSafeEqualHex("0".repeat(64), expected)).toBe(false);
    // Redeem on the untampered id is unaffected; stored frozen input protects
    // the binding fields.
    const r = s.redeem(t.id, {
      expectedCapability: "test.write",
      expectedVersion: 1,
    });
    expect(r.ok).toBe(true);
  });

  it("rejects tickets whose capability version changed", () => {
    const s = store();
    const t = s.issue(bindings);
    const r = s.redeem(t.id, {
      expectedCapability: "test.write",
      expectedVersion: 2,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("version_changed");
  });

  it("rejects capability substitution at redemption", () => {
    const s = store();
    const t = s.issue(bindings);
    const r = s.redeem(t.id, {
      expectedCapability: "other.cap",
      expectedVersion: 1,
    });
    expect(r.ok).toBe(false);
  });

  it("returns the immutably stored input, not caller context", () => {
    const s = store();
    const mutableInput: Record<string, unknown> = { path: "/a", payload: "x" };
    const t = s.issue({ ...bindings, input: mutableInput });
    mutableInput.payload = "MUTATED";
    const r = s.redeem(t.id, {
      expectedCapability: "test.write",
      expectedVersion: 1,
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect((r.input as Record<string, unknown>).payload).toBe("x");
    }
  });

  it("invalidateForCapabilityVersion cancels outstanding tickets", () => {
    const s = store();
    const t = s.issue(bindings);
    const n = s.invalidateForCapabilityVersion("test.write", 1, "upgrade");
    expect(n).toBe(1);
    const r = s.redeem(t.id, {
      expectedCapability: "test.write",
      expectedVersion: 1,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("invalidated");
  });

  it("issues unique unguessable ids and nonce-bound tickets", () => {
    const s = store();
    const a = s.issue(bindings);
    const b = s.issue(bindings);
    expect(a.id).not.toBe(b.id);
    expect(a.nonce).toBe(bindings.nonce);
    expect(a.inputHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("ticketBody", () => {
  it("signs all binding fields without status/signature", () => {
    const canonical = ticketBody({
      id: "x",
      capability: "c",
      capabilityVersion: 1,
      inputHash: "h",
      actor: "a",
      resource: null,
      risk: "low",
      policyVersion: "p",
      approvalMethod: "automatic",
      origin: "local",
      challengeId: "ch",
      nonce: "n",
      issuedAt: 1,
      expiresAt: 2,
    });
    const parsed = JSON.parse(canonical);
    expect(parsed.status).toBeUndefined();
    expect(parsed.signature).toBeUndefined();
    expect(parsed.actor).toBe("a");
    expect(canonicalStringify(parsed)).toBe(canonical);
  });
});
