import { describe, expect, it } from "vitest";
import { PolicyEngine } from "@rtq/policy";

function ctx(overrides: Partial<Parameters<PolicyEngine["evaluate"]>[0]> = {}) {
  return {
    capability: "files.delete",
    input: { path: "/workspace/x" },
    origin: "local" as const,
    risk: "medium" as const,
    resource: "/workspace/x",
    ...overrides,
  };
}

describe("PolicyEngine", () => {
  it("denies by default when no rule matches (secure default)", () => {
    const p = new PolicyEngine();
    const r = p.evaluate(ctx());
    expect(r.decision.decision).toBe("deny");
    if (r.decision.decision === "deny")
      expect(r.decision.code).toBe("policy.default_deny");
  });

  it("missing policy never becomes allow", () => {
    const p = new PolicyEngine();
    for (const risk of ["low", "medium", "high", "critical"] as const) {
      const r = p.evaluate(ctx({ risk }));
      expect(r.decision.decision).toBe("deny");
    }
  });

  it("deny rules win over allow rules", () => {
    const p = new PolicyEngine();
    p.allow("files.delete", undefined, { reason: "ok" });
    p.deny(
      "files.delete",
      { path: "/etc" },
      { code: "protected", reason: "no" },
    );
    const r = p.evaluate(ctx({ resource: "/etc/hosts" }));
    expect(r.decision.decision).toBe("deny");
  });

  it("allow rule permits, and origin/path conditions are honored", () => {
    const p = new PolicyEngine();
    p.allow("files.delete", { origin: "local" }, { reason: "local ok" });
    expect(p.evaluate(ctx({ origin: "local" })).decision.decision).toBe(
      "allow",
    );
    expect(p.evaluate(ctx({ origin: "remote" })).decision.decision).toBe(
      "deny",
    );
  });

  it("riskAtLeast conditions gate approval rules", () => {
    const p = new PolicyEngine();
    p.allow("files.delete", undefined, { reason: "base allow" });
    p.requireApproval(
      "files.delete",
      { riskAtLeast: "high" },
      { reason: "dangerous", strategy: "qr" },
    );
    const low = p.evaluate(ctx({ risk: "low" }));
    expect(low.decision.decision).toBe("allow");
    const high = p.evaluate(ctx({ risk: "high" }));
    expect(high.decision.decision).toBe("approval_required");
    if (high.decision.decision === "approval_required")
      expect(high.decision.strategy).toBe("qr");
  });

  it("requireVerification maps to device_verification by default", () => {
    const p = new PolicyEngine();
    p.allow("files.delete", undefined, { reason: "a" });
    p.requireVerification("files.delete", undefined, { reason: "verify" });
    const r = p.evaluate(ctx());
    expect(r.decision.decision).toBe("approval_required");
    if (r.decision.decision === "approval_required") {
      expect(r.decision.strategy).toBe("device_verification");
    }
  });

  it("requireClarification returns structured questions", () => {
    const p = new PolicyEngine();
    p.requireClarification("files.delete", undefined, {
      reason: "confirm target",
      questions: [{ field: "target", reason: "required" }],
    });
    const r = p.evaluate(ctx({ input: {}, resource: "/workspace" }));
    expect(r.decision.decision).toBe("clarification_required");
    if (r.decision.decision === "clarification_required") {
      expect(r.decision.questions).toHaveLength(1);
    }
  });

  it("policy-mandated risk override only raises, never lowers", () => {
    const p = new PolicyEngine();
    p.allow("files.delete", undefined, { reason: "a", risk: "high" });
    const r = p.evaluate(ctx({ risk: "low" }));
    expect(r.decision.decision).toBe("allow");
    if (r.decision.decision === "allow")
      expect(r.decision.overrides?.risk).toBe("high");
  });

  it("glob matching supports * and **", () => {
    const p = new PolicyEngine();
    p.deny("tools.**", undefined, { code: "x", reason: "no tools" });
    expect(
      p.evaluate({ ...ctx(), capability: "tools.exec" }).decision.decision,
    ).toBe("deny");
    expect(
      p.evaluate({ ...ctx(), capability: "tools.danger.exec" }).decision
        .decision,
    ).toBe("deny");
    expect(p.evaluate(ctx()).decision.decision).toBe("deny"); // different default deny reason
  });

  it("explicit defaultMode allow still honors deny rules", () => {
    const p = new PolicyEngine({ defaultMode: "allow" });
    p.deny("files.delete", { path: "/etc" }, { code: "x", reason: "no" });
    expect(p.evaluate(ctx({ resource: "/etc/hosts" })).decision.decision).toBe(
      "deny",
    );
    expect(p.evaluate(ctx()).decision.decision).toBe("allow");
  });
});
