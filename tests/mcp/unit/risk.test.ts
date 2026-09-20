import { describe, expect, it } from "vitest";
import {
  classifyEffectiveOperations,
  getEffectiveOperations,
  credentialClassSignal,
  McpRiskAdvisor,
  type McpEffectiveOperation,
} from "@rtq/mcp";

describe("classifyEffectiveOperations", () => {
  it("classifies a read tool as read-only", () => {
    const result = classifyEffectiveOperations(undefined, {
      name: "get_user",
      description: "Fetches a user record",
    });
    expect(result.operations).toContain("read");
    expect(result.appearsIrreversible).toBe(false);
    expect(result.requiresNetwork).toBe(false);
  });

  it("classifies a destructive tool as write + irreversible", () => {
    const result = classifyEffectiveOperations(undefined, {
      name: "delete_file",
      description: "Deletes a file from disk",
    });
    expect(result.operations).toContain("write");
    expect(result.appearsIrreversible).toBe(true);
    expect(result.strongestReason).toBe("strongly_irreversible");
  });

  it("classifies a network tool with network op", () => {
    const result = classifyEffectiveOperations(undefined, {
      name: "fetch_url",
      description: "HTTP fetch",
      declaredCapabilities: ["network"],
    });
    expect(result.operations).toContain("network");
    expect(result.requiresNetwork).toBe(true);
  });

  it("http transport implies requiresNetwork but does NOT add 'network' to operations", () => {
    const result = classifyEffectiveOperations(undefined, {
      name: "do_something",
    }, "http");
    expect(result.requiresNetwork).toBe(true);
    // "network" is only added via declaredCapabilities, not transport alone
    expect(result.operations).not.toContain("network");
  });

  it("stdio transport does NOT imply requiresNetwork", () => {
    const result = classifyEffectiveOperations(undefined, {
      name: "do_something",
    }, "stdio");
    expect(result.requiresNetwork).toBe(false);
  });

  it("classifies admin tools", () => {
    const result = classifyEffectiveOperations(undefined, {
      name: "grant_access",
      description: "Grants user access",
    });
    expect(result.operations).toContain("admin");
    expect(result.operations).toContain("credential");
  });

  it("unknown tool stays in unknown set", () => {
    const result = classifyEffectiveOperations(undefined, {
      name: "mystery_verb",
      description: "Does a mystery thing",
    });
    expect(result.operations).toContain("unknown");
  });
});

describe("getEffectiveOperations", () => {
  it("returns operations array", () => {
    const ops = getEffectiveOperations({ name: "read_file" });
    expect(Array.isArray(ops)).toBe(true);
    expect(ops.length).toBeGreaterThan(0);
  });

  it("passes transport to classifyEffectiveOperations", () => {
    const result = classifyEffectiveOperations(undefined, { name: "fetch_data" }, "http");
    expect(result.requiresNetwork).toBe(true);
  });
});

describe("credentialClassSignal", () => {
  it("returns undefined for undefined input", () => {
    expect(credentialClassSignal(undefined)).toBeUndefined();
  });

  it("returns undefined for non-admin/non-write credential class", () => {
    expect(credentialClassSignal("read")).toBeUndefined();
  });

  it("returns a signal for admin credential class", () => {
    const signal = credentialClassSignal("admin");
    expect(signal).toBeDefined();
    expect(signal!.factor).toBe("credential_class_admin");
  });

  it("returns a signal for write credential class", () => {
    const signal = credentialClassSignal("write");
    expect(signal).toBeDefined();
    expect(signal!.factor).toBe("credential_class_write");
  });
});

describe("McpRiskAdvisor", () => {
  it("advise returns McpRiskAdvice with effective and baseline", () => {
    const advisor = new McpRiskAdvisor();
    const advice = advisor.advise("medium", undefined, {
      name: "get_data",
      description: "Reads data",
    });
    expect(advice).toHaveProperty("effective");
    expect(advice).toHaveProperty("baseline");
    expect(advice).toHaveProperty("effectiveOperations");
    expect(advice.effectiveOperations).toContain("read");
    expect(advice.baseline).toBe("medium");
  });

  it("advise raises severity when risk signals are high", () => {
    const advisor = new McpRiskAdvisor();
    const advice = advisor.advise("low", undefined, {
      name: "delete_everything",
      description: "Destructive reset operation",
    });
    // "delete_everything" → appearsIrreversible=true, operations=["write"]
    // delta=1 (irreversible), low(1)+1=medium(2)
    expect(advice.effective).toBe("medium");
    expect(advice.appearsIrreversible).toBe(true);
    expect(advice.effectiveOperations).toContain("write");
  });
});
