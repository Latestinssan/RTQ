import { describe, expect, it } from "vitest";
import { ClarificationEngine } from "@rtq/clarification";

describe("ClarificationEngine", () => {
  it("asks for missing security-critical params and never authorizes", () => {
    const c = new ClarificationEngine();
    c.add({
      capability: "files.delete",
      field: "target",
      reason: "delete target must be explicit",
      type: "path",
    });
    const questions = c.evaluate("files.delete", {});
    expect(questions).toHaveLength(1);
    expect(questions[0]!.field).toBe("target");
    expect(c.isClarified("files.delete", {})).toBe(false);
  });

  it("is satisfied when the value is present and non-empty", () => {
    const c = new ClarificationEngine();
    c.add({ capability: "files.delete", field: "target", reason: "required" });
    expect(c.isClarified("files.delete", { target: "/workspace/a" })).toBe(
      true,
    );
  });

  it("supports custom satisfaction predicates", () => {
    const c = new ClarificationEngine();
    c.add({
      capability: "notify",
      field: "recipient",
      reason: "recipient must be explicit",
      isSatisfied: (v) =>
        typeof v === "string" && v.length >= 3 && v !== "everyone",
    });
    expect(c.isClarified("notify", { recipient: "everyone" })).toBe(false);
    expect(c.isClarified("notify", { recipient: "alice@example.com" })).toBe(
      true,
    );
    expect(c.isClarified("notify", { recipient: "x" })).toBe(false);
  });

  it("replaces duplicate rules for the same field", () => {
    const c = new ClarificationEngine();
    c.add({ capability: "a", field: "f", reason: "one" });
    c.add({ capability: "a", field: "f", reason: "two" });
    expect(c.rulesFor("a")).toHaveLength(1);
    expect(c.ruleCount).toBe(1);
  });

  it("addMany registers across capabilities", () => {
    const c = new ClarificationEngine();
    c.addMany([
      { capability: "a", field: "x", reason: "r" },
      { capability: "b", field: "y", reason: "r" },
    ]);
    expect(c.ruleCount).toBe(2);
  });
});
