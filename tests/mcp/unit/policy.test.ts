import { describe, expect, it } from "vitest";
import {
  McpPolicyEngine,
  matchesMcpPattern,
  type McpPolicyRule,
  type McpEffectiveOperation,
} from "@rtq/mcp";
import { mcpAdvice } from "../helpers/risk-advice";

describe("matchesMcpPattern", () => {
  it("wildcard matches everything", () => {
    expect(matchesMcpPattern("*", "mcp://srv1/toolA")).toBe(true);
  });

  it("exact match", () => {
    expect(matchesMcpPattern("mcp://srv1/toolA", "mcp://srv1/toolA")).toBe(
      true,
    );
  });

  it("prefix match with trailing star", () => {
    expect(matchesMcpPattern("mcp://srv1/*", "mcp://srv1/toolA")).toBe(true);
  });

  it("prefix mismatch", () => {
    expect(matchesMcpPattern("mcp://srv2/*", "mcp://srv1/toolA")).toBe(false);
  });

  it("no match without star", () => {
    expect(matchesMcpPattern("mcp://srv1/toolA", "mcp://srv1/toolB")).toBe(
      false,
    );
  });

  it("prefix star matches trailing characters", () => {
    expect(matchesMcpPattern("mcp://srv1/tool*", "mcp://srv1/toolA")).toBe(
      true,
    );
  });
});

describe("McpPolicyEngine", () => {
  it("deny-all by default (fail-closed)", () => {
    const engine = new McpPolicyEngine();
    const result = engine.evaluate({
      capabilityName: "mcp://srv1/test",
      serverId: "srv1",
      toolName: "test",
    });
    expect(result.allowed).toBe(false);
  });

  it("explicit allow rule permits a tool", () => {
    const engine = new McpPolicyEngine({
      rules: [
        {
          instrument: "tool",
          pattern: "mcp://srv1/read_*",
          allow: true,
          reason: "read tools OK",
        },
      ],
      allowedEffectiveOperations: new Map([["read", ["mcp://*/*"]]]),
    });
    const result = engine.evaluate({
      capabilityName: "mcp://srv1/read_file",
      serverId: "srv1",
      toolName: "read_file",
      riskAdvice: mcpAdvice("low", ["read"]),
    });
    expect(result.allowed).toBe(true);
  });

  it("deny rule blocks a tool", () => {
    const engine = new McpPolicyEngine({
      rules: [
        {
          instrument: "tool",
          pattern: "mcp://srv1/delete_*",
          allow: false,
          reason: "no deletes",
        },
      ],
    });
    const result = engine.evaluate({
      capabilityName: "mcp://srv1/delete_file",
      serverId: "srv1",
      toolName: "delete_file",
    });
    expect(result.allowed).toBe(false);
  });

  it("transport gate denies http by default", () => {
    const engine = new McpPolicyEngine();
    const result = engine.evaluate({
      capabilityName: "mcp://srv1/test",
      serverId: "srv1",
      toolName: "test",
      transportKind: "http",
    });
    expect(result.allowed).toBe(false);
  });

  it("unknown effective operation denied (fail-closed)", () => {
    const engine = new McpPolicyEngine({
      rules: [{ instrument: "tool", pattern: "*", allow: true }],
    });
    const result = engine.evaluate({
      capabilityName: "mcp://srv1/test",
      serverId: "srv1",
      toolName: "test",
      riskAdvice: mcpAdvice("low", ["unknown"]),
    });
    expect(result.allowed).toBe(false);
  });

  it("tenant allowlist blocks unknown tenants", () => {
    const engine = new McpPolicyEngine({
      rules: [{ instrument: "tool", pattern: "*", allow: true }],
      allowedTenants: new Set(["tenant-a"]),
      allowedEffectiveOperations: new Map([["read", ["mcp://*/*"]]]),
    });
    const result = engine.evaluate({
      capabilityName: "mcp://srv1/test",
      serverId: "srv1",
      toolName: "test",
      tenant: "tenant-b",
      riskAdvice: mcpAdvice("low", ["read"]),
    });
    expect(result.allowed).toBe(false);
  });

  it("getLimits returns configured limits", () => {
    const engine = new McpPolicyEngine({
      limits: { maxResultSizeBytes: 512 },
    });
    expect(engine.getLimits().maxResultSizeBytes).toBe(512);
  });

  it("approvalTierFor returns mapped tier or fail-closed default", () => {
    const engine = new McpPolicyEngine({
      approvalTier: new Map([["high", "user_confirmation"]]),
    });
    expect(engine.approvalTierFor("high")).toBe("user_confirmation");
    // "low" has no explicit mapping but has a fail-closed default
    expect(engine.approvalTierFor("low")).toBe("automatic");
    expect(engine.approvalTierFor("critical")).toBe("device_verification");
  });
});
