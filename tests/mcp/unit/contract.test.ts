import { describe, expect, it } from "vitest";
import {
  McpRegistry,
  runContractCheck,
  runContractChecksForAll,
  normalizeToolSchema,
  computeToolSchemaHash,
  type McpServerConfig,
  type McpToolMeta,
  type McpToolRecord,
} from "@rtq/mcp";

function config(over: Partial<McpServerConfig> = {}): McpServerConfig {
  return {
    serverId: "srv-1",
    name: "test-server",
    version: "1.0.0",
    transport: { kind: "in-memory", host: null },
    ...over,
  };
}

function toolMeta(over: Partial<McpToolMeta> = {}): McpToolMeta {
  const name = over.name ?? "read_file";
  const description = over.description ?? "Reads a file";
  const rawSchema = over.rawSchema ?? {
    type: "object",
    properties: { path: { type: "string" } },
    required: ["path"],
  };
  const normalizedSchema = normalizeToolSchema(rawSchema).schema;
  const schemaHash = computeToolSchemaHash({
    name,
    description,
    normalizedSchema,
  });
  return {
    name,
    description,
    rawSchema,
    normalizedSchema,
    schemaHash,
    protocolVersion: "2025-06-18",
    incomplete: false,
    ...over,
  };
}

describe("runContractCheck", () => {
  it("passes for a well-formed tool", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const record = registry.registerTool("srv-1", toolMeta());
    const report = runContractCheck(record);
    expect(report.passed).toBe(true);
    expect(report.checks).toHaveLength(5);
    for (const check of report.checks) {
      expect(check.passed).toBe(true);
    }
  });

  it("fails for incomplete schema", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const record = registry.registerTool(
      "srv-1",
      toolMeta({ incomplete: true }),
    );
    const report = runContractCheck(record);
    expect(report.passed).toBe(false);
    const completenessCheck = report.checks.find(
      (c) => c.checkId === "schema_completeness",
    );
    expect(completenessCheck?.passed).toBe(false);
  });

  it("fails for malformed capability name", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const record = registry.registerTool("srv-1", toolMeta());
    // Manually corrupt the capability name
    (record as any).capabilityName = "spaces not allowed!";
    const report = runContractCheck(record);
    expect(report.passed).toBe(false);
    const capCheck = report.checks.find((c) => c.checkId === "capability_name");
    expect(capCheck?.passed).toBe(false);
  });

  it("marks needsReevaluation on failure", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const record = registry.registerTool(
      "srv-1",
      toolMeta({ incomplete: true }),
    );
    expect(record.needsReevaluation).toBe(true);
  });

  it("passes for mcp:// URI capability names", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const record = registry.registerTool("srv-1", toolMeta());
    (record as any).capabilityName = "mcp://srv-1/read_file";
    const report = runContractCheck(record);
    const capCheck = report.checks.find((c) => c.checkId === "capability_name");
    expect(capCheck?.passed).toBe(true);
  });
});

describe("runContractChecksForAll", () => {
  it("checks all tools across all servers", () => {
    const registry = new McpRegistry();
    registry.registerServer(config({ serverId: "srv-1" }));
    registry.registerServer(config({ serverId: "srv-2" }));
    registry.registerTool("srv-1", toolMeta({ name: "tool_a" }));
    registry.registerTool("srv-2", toolMeta({ name: "tool_b" }));

    const reports = runContractChecksForAll(registry);
    expect(reports).toHaveLength(2);
    for (const report of reports) {
      expect(report.passed).toBe(true);
    }
  });

  it("returns empty array for empty registry", () => {
    const registry = new McpRegistry();
    expect(runContractChecksForAll(registry)).toHaveLength(0);
  });
});
