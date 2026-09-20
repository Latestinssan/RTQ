import { describe, expect, it } from "vitest";
import {
  McpRegistry,
  computeToolSchemaHash,
  normalizeToolSchema,
  serverProfileHash,
  type McpRegistryEvent,
  type McpServerConfig,
  type McpServerIdentity,
  type McpToolMeta,
} from "@rtq/mcp";

function config(over: Partial<McpServerConfig> = {}): McpServerConfig {
  return {
    serverId: "srv-1",
    name: "demo",
    version: "1.0.0",
    transport: { kind: "http", url: "https://mcp.example.com" },
    auth: { method: "bearer", credentialRef: "ref://vault/x" },
    defaultSeverity: "high",
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
  const normalized = normalizeToolSchema(rawSchema);
  const schemaHash =
    over.schemaHash ??
    computeToolSchemaHash({
      name,
      description,
      normalizedSchema: normalized.schema,
      declaredCapabilities: [],
    });
  return {
    name,
    description,
    rawSchema,
    normalizedSchema: normalized.schema,
    schemaHash,
    protocolVersion: over.protocolVersion ?? "2025-06-18",
    incomplete: over.incomplete ?? normalized.incomplete,
    declaredCapabilities: over.declaredCapabilities ?? [],
  };
}

const baseIdentity: McpServerIdentity = {
  stableId: "srv-1",
  name: "demo",
  version: "1.0.0",
  transport: "http",
  endpoint: "https://mcp.example.com",
  authMethod: "bearer",
  identityMaterial: "fp-1",
  identityVerified: true,
};

describe("McpRegistry", () => {
  it("registers a server in pending trust state and bumps the epoch", () => {
    const registry = new McpRegistry();
    expect(registry.getEpoch()).toBe(0);
    const record = registry.registerServer(config());
    expect(record.serverId).toBe("srv-1");
    expect(record.trustState).toBe("pending");
    expect(record.needsReapproval).toBe(true);
    expect(record.tools.size).toBe(0);
    expect(registry.getEpoch()).toBe(1);
  });

  it("accepts an explicitly approved initial trust as not needing reapproval", () => {
    const registry = new McpRegistry();
    const record = registry.registerServer(
      config({ initialTrust: "approved" }),
    );
    expect(record.trustState).toBe("approved");
    expect(record.needsReapproval).toBe(false);
  });

  it("re-registering with an unchanged profile is idempotent (no epoch bump)", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const epochBefore = registry.getEpoch();
    const again = registry.registerServer(config());
    expect(again.serverId).toBe("srv-1");
    expect(registry.getEpoch()).toBe(epochBefore);
  });

  it("a security-relevant profile change marks needsReapproval and bumps epoch", () => {
    const registry = new McpRegistry();
    const before = registry.registerServer(config());
    const epochBefore = registry.getEpoch();
    const updated = registry.registerServer(
      config({
        auth: { method: "mtls" },
        transport: { kind: "stdio", command: "node", args: ["mcp.js"] },
      }),
    );
    expect(updated.identity.transport).toBe("stdio");
    expect(updated.profileHash).not.toBe(before.profileHash);
    expect(updated.needsReapproval).toBe(true);
    expect(registry.getEpoch()).toBe(epochBefore + 1);
  });

  it("keeps registered tools when a non-security update re-registers a server", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    registry.registerTool("srv-1", toolMeta());
    const again = registry.registerServer(config());
    expect(again.tools.size).toBe(1);
  });

  it("enforces legal trust transitions only", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const approved = registry.setTrustState("srv-1", "approved");
    expect(approved).toEqual({ ok: true });
    const revoked = registry.setTrustState("srv-1", "revoked");
    expect(revoked.ok).toBe(true);
    const reVerify = registry.setTrustState("srv-1", "pending");
    expect(reVerify.ok).toBe(true);
    const blocked = registry.setTrustState("srv-1", "blocked");
    expect(blocked.ok).toBe(true);
    // blocked is terminal
    const revive = registry.setTrustState("srv-1", "approved");
    expect(revive.ok).toBe(false);
    expect(revive.reason).toMatch(/illegal_transition/);
  });

  it("a same-state trust transition is a no-op", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const epoch = registry.getEpoch();
    expect(registry.setTrustState("srv-1", "pending")).toEqual({ ok: true });
    expect(registry.getEpoch()).toBe(epoch);
  });

  it("returns unknown_server for unregistered servers", () => {
    const registry = new McpRegistry();
    expect(registry.setTrustState("ghost", "approved")).toEqual({
      ok: false,
      reason: "unknown_server",
    });
  });

  it("registers a discovered tool as non-executable with a capability name", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const epochAfterServer = registry.getEpoch();
    const tool = registry.registerTool("srv-1", toolMeta());
    expect(tool.name).toBe("read_file");
    expect(tool.capabilityName).toBe("mcp://srv-1/read_file");
    expect(tool.capabilityVersion).toBe(1);
    expect(tool.metaRevision).toBe(1);
    expect(tool.registered).toBe(false);
    // Registering a new tool is a security-relevant change: epoch advances.
    expect(registry.getEpoch()).toBe(epochAfterServer + 1);
  });

  it("re-registering a tool with the same schema hash is idempotent", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const meta = toolMeta();
    const tool = registry.registerTool("srv-1", meta);
    const epoch = registry.getEpoch();
    const again = registry.registerTool("srv-1", meta);
    expect(again).toBe(tool);
    expect(registry.getEpoch()).toBe(epoch);
  });

  it("a schema change bumps metaRevision and invalidates the prior binding", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const first = registry.registerTool("srv-1", toolMeta());
    const changed = registry.registerTool(
      "srv-1",
      toolMeta({
        rawSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
            mode: { type: "string" },
          },
          required: ["path"],
        },
      }),
    );
    expect(changed.metaRevision).toBe(2);
    expect(changed.schemaHash).not.toBe(first.schemaHash);
    // capabilityVersion is assigned once and does not auto-bump with schema
    // changes — metaRevision is the security-relevant change detector.
    expect(changed.capabilityVersion).toBe(1);
  });

  it("marks tools with unsupported schema constructs incomplete", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    const tool = registry.registerTool(
      "srv-1",
      toolMeta({
        rawSchema: {
          type: "object",
          properties: { a: { $ref: "#/defs/x" } },
        },
      }),
    );
    expect(tool.incomplete).toBe(true);
    expect(tool.needsReevaluation).toBe(true);
  });

  it("registers a tool as executable only via the explicit gateway step", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    registry.registerTool("srv-1", toolMeta());
    const registered = registry.registerToolAsExecutable("srv-1", "read_file");
    expect(registered?.registered).toBe(true);
    expect(registered?.registeredAt).toBeGreaterThan(0);
    expect(registered?.needsReevaluation).toBe(false);
  });

  it("registering a tool on an unknown server throws", () => {
    const registry = new McpRegistry();
    expect(() => registry.registerTool("ghost", toolMeta())).toThrow(
      /unknown server/,
    );
  });

  it("revokeServer revokes the server and reports tool count", () => {
    const registry = new McpRegistry();
    registry.registerServer(config());
    registry.registerTool("srv-1", toolMeta());
    registry.registerTool("srv-1", toolMeta({ name: "write_file" }));
    const count = registry.revokeServer("srv-1");
    expect(count).toBe(2);
    expect(registry.getServer("srv-1")?.trustState).toBe("revoked");
  });

  it("fires post-commit onChange events", () => {
    const events: McpRegistryEvent[] = [];
    const registry = new McpRegistry();
    registry.onChange = (event) => events.push(event);
    registry.registerServer(config());
    registry.registerTool("srv-1", toolMeta());
    registry.setTrustState("srv-1", "approved");
    expect(events.map((e) => e.kind)).toEqual([
      "server_registered",
      "tool_registered",
      "server_trust_changed",
    ]);
    expect(events.every((e) => e.epoch <= registry.getEpoch())).toBe(true);
  });
});

describe("serverProfileHash", () => {
  it("is stable for identical identities", () => {
    expect(serverProfileHash(baseIdentity)).toBe(
      serverProfileHash(baseIdentity),
    );
  });

  it("changes when security-relevant identity fields change", () => {
    const changed = serverProfileHash({ ...baseIdentity, transport: "stdio" });
    expect(changed).not.toBe(serverProfileHash(baseIdentity));
  });

  it("changes when extended operand facts (auth/tenant) change", () => {
    const a = serverProfileHash(baseIdentity, { auth: "mtls" });
    const b = serverProfileHash(baseIdentity, { auth: "bearer" });
    expect(a).not.toBe(b);
    const tenant = serverProfileHash(baseIdentity, { tenant: "acme" });
    expect(tenant).not.toBe(serverProfileHash(baseIdentity, {}));
  });
});
