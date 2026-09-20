import { describe, expect, it } from "vitest";
import {
  canonicalStringify,
  sha256Hex,
  hmacSha256Hex,
  timingSafeEqualHex,
  randomHex,
  redactValue,
  redactString,
  signCanonical,
  verifySignature,
  inputHash,
  deepFreeze,
} from "@rtq/crypto";

describe("canonicalStringify", () => {
  it("is deterministic regardless of key insertion order, including nested objects", () => {
    const a = { b: 1, a: { d: "x", c: [1, 2, { g: 0, f: true }] } };
    const b = { a: { c: [1, 2, { f: true, g: 0 }], d: "x" }, b: 1 };
    expect(canonicalStringify(a)).toBe(canonicalStringify(b));
  });

  it("serializes booleans/numbers consistently", () => {
    expect(canonicalStringify(true)).toBe("true");
    expect(canonicalStringify(false)).toBe("false");
    expect(canonicalStringify(42)).toBe("42");
  });

  it("rejects non-finite numbers (would silently become null in JSON)", () => {
    expect(() => canonicalStringify({ a: NaN })).toThrow();
    expect(() => canonicalStringify({ a: Infinity })).toThrow();
  });

  it("handles undefined and null uniformly", () => {
    expect(canonicalStringify(undefined)).toBe("null");
    expect(canonicalStringify(null)).toBe("null");
  });
});

describe("hashing", () => {
  it("sha256Hex is stable", () => {
    expect(sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("timingSafeEqualHex rejects length mismatches without throwing", () => {
    expect(timingSafeEqualHex("aa", "aaaa")).toBe(false);
    expect(timingSafeEqualHex("", "")).toBe(false);
    expect(timingSafeEqualHex("aa", "aa")).toBe(true);
  });

  it("randomHex produces unique values of requested size", () => {
    expect(randomHex(16)).toHaveLength(32);
    expect(randomHex(16)).not.toBe(randomHex(16));
  });

  it("signCanonical/verifySignature round-trip", () => {
    const key = "test-key";
    const sig = signCanonical(key, { a: 1, b: "x" });
    expect(verifySignature(key, { b: "x", a: 1 }, sig)).toBe(true);
    expect(verifySignature(key, { b: "x", a: 2 }, sig)).toBe(false);
    expect(verifySignature("other-key", { a: 1, b: "x" }, sig)).toBe(false);
  });

  it("inputHash is canonical", () => {
    expect(inputHash({ a: 1, b: [2, 3] })).toBe(inputHash({ b: [2, 3], a: 1 }));
  });

  it("HMAC depends on both key and message", () => {
    expect(hmacSha256Hex("k1", "msg")).not.toBe(hmacSha256Hex("k2", "msg"));
    expect(hmacSha256Hex("k1", "msg")).not.toBe(hmacSha256Hex("k1", "msg2"));
  });
});

describe("redaction", () => {
  it("redacts secret field names recursively", () => {
    const out = redactValue({
      apiKey: "sk-1234567890",
      nested: { password: "hunter2", public: "keep" },
      list: [{ token: "abc" }],
    });
    expect(out).toEqual({
      apiKey: "[REDACTED]",
      nested: { password: "[REDACTED]", public: "keep" },
      list: [{ token: "[REDACTED]" }],
    });
  });

  it("redacts secret-shaped strings", () => {
    expect(redactString("auth Bearer abcdefghij")).toBe("auth [REDACTED]");
    expect(redactString("AKIAIOSFODNN7EXAMPLE")).toBe("[REDACTED]");
    expect(
      redactString(
        "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
      ),
    ).toContain("[REDACTED]");
  });

  it("does not mutate the original object", () => {
    const orig = { apiKey: "x" };
    redactValue(orig);
    expect(orig.apiKey).toBe("x");
  });

  it("redacts extra secret values by string match", () => {
    expect(
      redactString(
        "value is abcdefgh-secret-end",
        new Set(["abcdefgh-secret-end"]),
      ),
    ).toBe("value is [REDACTED]");
  });
});

describe("deepFreeze", () => {
  it("returns a deep-frozen copy", () => {
    const input = { a: { b: [1, 2] } };
    const frozen = deepFreeze(input);
    expect(Object.isFrozen(frozen)).toBe(true);
    expect(Object.isFrozen(frozen.a)).toBe(true);
    expect(Object.isFrozen(frozen.a.b)).toBe(true);
    expect(() => {
      (frozen.a as { b: unknown[] }).b.push(3);
    }).toThrow();
    // Original untouched.
    expect((input.a as { b: unknown[] }).b).toHaveLength(2);
  });
});
