import { describe, expect, it } from "vitest";
import { RiskEngine } from "@rtq/risk";
import type { RiskCapabilityFactors } from "@rtq/core";

const base: RiskCapabilityFactors = { base: "low" };

describe("RiskEngine", () => {
  it("evaluates plain low risk without contributions", () => {
    const e = new RiskEngine().evaluate(base, "low", { origin: "local" });
    expect(e.level).toBe("low");
    expect(e.baseLevel).toBe("low");
  });

  it("never lets a caller-claimed LOW risk downgrade a computed risk", () => {
    const e = new RiskEngine().evaluate(
      base,
      "low",
      { origin: "remote" },
      "low",
    );
    expect(e.level).toBe("medium");
  });

  it("escalates untrusted origins", () => {
    const engine = new RiskEngine();
    expect(engine.evaluate(base, "low", { origin: "remote" }).level).toBe(
      "medium",
    );
    expect(engine.evaluate(base, "low", { origin: "mobile" }).level).toBe(
      "medium",
    );
    expect(engine.evaluate(base, "low", { origin: "unknown" }).level).toBe(
      "medium",
    );
    expect(engine.evaluate(base, "low", { origin: "agent" }).level).toBe(
      "medium",
    );
  });

  it("treats unknown origin as untrusted, never local", () => {
    const e = new RiskEngine().evaluate(base, "low", { origin: "unknown" });
    expect(e.level).not.toBe("low");
    expect(e.contributions.some((c) => c.factor === "origin")).toBe(true);
  });

  it("composes multiple factors up to critical", () => {
    const e = new RiskEngine().evaluate(base, "low", {
      origin: "remote",
      reversible: false,
      dataSensitivity: "critical",
      financialImpact: true,
      privilegeImpact: true,
      requiresNetwork: true,
      touchesSystem: true,
    });
    expect(e.level).toBe("critical");
  });

  it("raises risk for sensitive resource prefixes", () => {
    const e = new RiskEngine().evaluate(base, "low", {
      resource: "/etc/passwd",
    });
    expect(e.level).toBe("medium");
  });

  it("caps at critical", () => {
    const e = new RiskEngine().evaluate(base, "high", {
      dataSensitivity: "critical",
      financialImpact: true,
      privilegeImpact: true,
      reversible: false,
      origin: "remote",
    });
    expect(e.level).toBe("critical");
  });

  it("records contributions and policy version", () => {
    const engine = new RiskEngine({ policyVersion: "risk-v9" });
    const e = engine.evaluate(base, "low", { reversible: false });
    expect(e.policyVersion).toBe("risk-v9");
    expect(e.contributions).toEqual([
      { factor: "reversibility", detail: expect.any(String) },
    ]);
  });

  it("applies custom origin escalation maps", () => {
    const engine = new RiskEngine({ originEscalation: { remote: 2 } });
    expect(engine.evaluate(base, "low", { origin: "remote" }).level).toBe(
      "high",
    );
  });
});
