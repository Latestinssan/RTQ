/**
 * RTQ MCP security matrix — spec 46.30 (35 items).
 *
 * These tests verify the security invariants that the MCP gateway and its
 * supporting modules enforce. Each test maps to a specific invariant from
 * the spec; the matrix is designed to catch regressions in fail-closed
 * behavior, ticket hygiene, schema hardening, and isolation.
 *
 * Categories:
 *  1–7:   Unknown server/tool/operation → denied
 *  8–12:  Ticket hygiene (single-use, non-replayable, bound)
 * 13–17:  Schema hardening (incomplete, unsafe, extra fields)
 * 18–22:  Result normalization (size, depth, redaction, truncation)
 * 23–27:  Policy engine (fail-closed, transport gate, tenant gate)
 * 28–31:  Credential isolation (vault, scope, expiry, revocation)
 * 32–35:  Risk advisory (raise-only, never authorize, classification)
 */

import { describe, expect, it, vi } from "vitest";
import {
  // Core modules
  McpRegistry,
  McpPolicyEngine,
  McpRiskAdvisor,
  McpGateway,
  InMemoryCredentialVault,
  // Helpers
  normalizeToolSchema,
  computeToolSchemaHash,
  validateToolArguments,
  normalizeMcpResult,
  runContractCheck,
  classifyEffectiveOperations,
  credentialClassSignal,
  // Types
  type McpServerConfig,
  type McpToolMeta,
  type McpConnection,
  type McpGatewayConfig,
  type McpEffectiveOperation,
} from "@rtq/mcp";

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

const DEFAULT_SERVER: McpServerConfig = {
  serverId: "test-server",
  name: "test",
  version: "1.0.0",
  transport: { kind: "in-memory", host: null },
  defaultSeverity: "medium",
};

function mockConn(overrides: Record<string, unknown> = {}): McpConnection {
  return {
    kind: "in-memory",
    protocolLimits: { maxMessageSizeBytes: 1024 * 1024 },
    connect: vi.fn().mockResolvedValue(undefined),
    request: vi.fn().mockResolvedValue({ tools: [] }),
    notify: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  } as unknown as McpConnection;
}

function makeToolMeta(over: Partial<McpToolMeta> = {}): McpToolMeta {
  const name = over.name ?? "read_file";
  return {
    name,
    description: over.description ?? "Reads a file",
    rawSchema: over.rawSchema ?? {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    normalizedSchema: over.normalizedSchema ?? {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
    schemaHash: over.schemaHash ?? `hash_${name}`,
    protocolVersion: "2025-06-18",
    incomplete: over.incomplete ?? false,
    ...over,
  };
}

function makeGateway(overrides: Partial<McpGatewayConfig> = {}) {
  const tickets = new Map<string, unknown>();
  const authorizeCalls: unknown[] = [];
  const executeCalls: string[] = [];
  const auditEvents: Array<{ event: string; data: Record<string, unknown> }> = [];

  const config: McpGatewayConfig & {
    _authorizeCalls: typeof authorizeCalls;
    _executeCalls: typeof executeCalls;
    _tickets: typeof tickets;
    _auditEvents: typeof auditEvents;
  } = {
    registry: new McpRegistry(),
    policy: new McpPolicyEngine({
      rules: [{ instrument: "tool", pattern: "*", allow: true }],
      allowedEffectiveOperations: new Map([
        ["read", ["mcp://*/*"]],
        ["write", ["mcp://*/*"]],
        ["network", ["mcp://*/*"]],
        ["admin", ["mcp://*/*"]],
        ["credential", ["mcp://*/*"]],
      ]),
    }),
    riskAdvisor: new McpRiskAdvisor(),
    authorize: vi.fn().mockImplementation(async (params: any) => {
      authorizeCalls.push(params);
      return { ticketId: `tkt_${authorizeCalls.length}`, approvalRequired: false };
    }),
    execute: vi.fn().mockImplementation(async (ticketId: string) => {
      executeCalls.push(ticketId);
      return { result: { ok: true } };
    }),
    tickets: {
      peek: (id: string) => tickets.get(id),
      park: (id: string, v: unknown) => { tickets.set(id, v); },
    },
    defaultLimits: { maxResultSizeBytes: 64 * 1024 },
    onAudit: (event, data) => { auditEvents.push({ event, data }); },
    _authorizeCalls: authorizeCalls,
    _executeCalls: executeCalls,
    _tickets: tickets,
    _auditEvents: auditEvents,
    ...overrides,
  } as any;

  const gw = new McpGateway(config);
  return { gw, config };
}

// ===========================================================================
// 1–7: Unknown server/tool/operation → denied
// ===========================================================================

describe("46.30 Security Matrix — Unknown entity denial", () => {
  // #1: Unknown server → denied
  it("#1 invoke on unknown server returns denied", async () => {
    const { gw } = makeGateway();
    const result = await gw.invoke("nonexistent", "tool", {});
    expect(result.status).toBe("denied");
  });

  // #2: Unknown tool → denied
  it("#2 invoke on unregistered tool returns denied", async () => {
    const { gw } = makeGateway();
    await gw.connect("srv-1", mockConn(), { config: DEFAULT_SERVER });
    const result = await gw.invoke("srv-1", "nonexistent_tool", {});
    expect(result.status).toBe("denied");
  });

  // #3: Discover on unknown session → empty
  it("#3 discover on unknown session returns empty", async () => {
    const { gw } = makeGateway();
    const tools = await gw.discover("nonexistent_session");
    expect(tools).toHaveLength(0);
  });

  // #4: Submit approval for unknown ticket → denied
  it("#4 submitApproval for unknown ticket returns denied", async () => {
    const { gw } = makeGateway();
    const result = await gw.submitApproval("fake_ticket", true);
    expect(result.status).toBe("denied");
  });

  // #5: Incomplete schema tool → denied by contract check
  it("#5 incomplete schema tool fails contract check", async () => {
    const registry = new McpRegistry();
    registry.registerServer(DEFAULT_SERVER);
    const tool = registry.registerTool("test-server", makeToolMeta({ incomplete: true }));
    const report = runContractCheck(tool);
    expect(report.passed).toBe(false);
    expect(tool.needsReevaluation).toBe(true);
  });

  // #6: Unknown effective operation → denied by policy
  it("#6 unknown effective operation denied by policy", () => {
    const engine = new McpPolicyEngine({
      rules: [{ instrument: "tool", pattern: "*", allow: true }],
    });
    const result = engine.evaluate({
      capabilityName: "mcp://srv/tool",
      serverId: "srv",
      toolName: "tool",
      riskAdvice: {
        severity: "low",
        effectiveOperations: ["unknown"],
        riskContributions: [],
      },
    });
    expect(result.allowed).toBe(false);
  });

  // #7: Unregistered tool in registry → getTool returns undefined
  it("#7 getTool on unregistered name returns undefined", () => {
    const registry = new McpRegistry();
    registry.registerServer(DEFAULT_SERVER);
    expect(registry.getTool("test-server", "nope")).toBeUndefined();
  });
});

// ===========================================================================
// 8–12: Ticket hygiene
// ===========================================================================

describe("46.30 Security Matrix — Ticket hygiene", () => {
  // #8: Each invoke produces a unique ticket ID
  it("#8 each invoke produces unique ticket IDs", async () => {
    const { gw } = makeGateway();
    await gw.connect("test-server", mockConn());
    gw["config"].registry.registerTool("test-server", makeToolMeta());

    const r1 = await gw.invoke("test-server", "read_file", { path: "/a" });
    const r2 = await gw.invoke("test-server", "read_file", { path: "/b" });
    expect(r1.status).toBe("executed");
    expect(r2.status).toBe("executed");
    expect((r1 as any).ticketId).not.toBe((r2 as any).ticketId);
  });

  // #9: Ticket is bound to specific server + tool + schema hash
  it("#9 ticket bindings contain serverId, toolName, schemaHash", async () => {
    const { gw, config } = makeGateway();
    await gw.connect("test-server", mockConn());
    config.registry.registerTool("test-server", makeToolMeta());

    await gw.invoke("test-server", "read_file", { path: "/a" });
    const authCall = config._authorizeCalls[0];
    expect(authCall.metadata.mcp.serverId).toBe("test-server");
    expect(authCall.metadata.mcp.toolName).toBe("read_file");
    expect(typeof authCall.metadata.mcp.schemaHash).toBe("string");
  });

  // #10: Ticket contains argument hash for idempotency
  it("#10 ticket bindings contain argumentsHash", async () => {
    const { gw, config } = makeGateway();
    await gw.connect("test-server", mockConn());
    config.registry.registerTool("test-server", makeToolMeta());

    await gw.invoke("test-server", "read_file", { path: "/a" });
    const authCall = config._authorizeCalls[0];
    expect(typeof authCall.metadata.mcp.argumentsHash).toBe("string");
    expect(authCall.metadata.mcp.argumentsHash.length).toBeGreaterThan(0);
  });

  // #11: Same arguments produce same hash (deterministic)
  it("#11 same arguments produce same argumentsHash", async () => {
    const { gw, config } = makeGateway();
    await gw.connect("test-server", mockConn());
    config.registry.registerTool("test-server", makeToolMeta());

    await gw.invoke("test-server", "read_file", { path: "/x" });
    await gw.invoke("test-server", "read_file", { path: "/x" });
    expect(config._authorizeCalls[0].metadata.mcp.argumentsHash)
      .toBe(config._authorizeCalls[1].metadata.mcp.argumentsHash);
  });

  // #12: Approval-required ticket is parked, not auto-executed
  it("#12 approval_required parks ticket and returns without execution", async () => {
    const { gw, config } = makeGateway({
      authorize: vi.fn().mockResolvedValue({ ticketId: "tkt_parked", approvalRequired: true }),
    });
    await gw.connect("test-server", mockConn());
    config.registry.registerTool("test-server", makeToolMeta());

    const result = await gw.invoke("test-server", "read_file", { path: "/a" });
    expect(result.status).toBe("approval_required");
    expect(config._executeCalls).toHaveLength(0);
    expect(config._tickets.has("tkt_parked")).toBe(true);
  });
});

// ===========================================================================
// 13–17: Schema hardening
// ===========================================================================

describe("46.30 Security Matrix — Schema hardening", () => {
  // #13: Schema with unsafe key is marked incomplete
  it("#13 unsafe constructor key marks schema incomplete", () => {
    // Use Object.defineProperty because { constructor: ... } in object literal
    // is a normal property, but __proto__ in object literal is special syntax.
    const schema: Record<string, unknown> = { type: "object", properties: {} };
    const props = schema.properties as Record<string, unknown>;
    Object.defineProperty(props, "__proto__", {
      value: { type: "string" },
      enumerable: true,
      configurable: true,
    });
    const result = normalizeToolSchema(schema);
    expect(result.incomplete).toBe(true);
    expect(result.reasons.some((r) => r.includes("__proto__"))).toBe(true);
  });

  // #14: Schema with constructor key is marked incomplete
  it("#14 unsafe constructor key marks schema incomplete", () => {
    const result = normalizeToolSchema({
      type: "object",
      properties: { constructor: { type: "string" } },
    });
    expect(result.incomplete).toBe(true);
  });

  // #15: Schema hash is deterministic (same input → same hash)
  it("#15 schema hash is deterministic", () => {
    const schema = { type: "object", properties: { x: { type: "string" } } };
    const h1 = computeToolSchemaHash({ name: "t", description: "d", normalizedSchema: schema });
    const h2 = computeToolSchemaHash({ name: "t", description: "d", normalizedSchema: schema });
    expect(h1).toBe(h2);
  });

  // #16: Schema hash changes when name changes
  it("#16 schema hash changes when name changes", () => {
    const schema = { type: "object", properties: { x: { type: "string" } } };
    const h1 = computeToolSchemaHash({ name: "a", description: "d", normalizedSchema: schema });
    const h2 = computeToolSchemaHash({ name: "b", description: "d", normalizedSchema: schema });
    expect(h1).not.toBe(h2);
  });

  // #17: Argument validation rejects invalid types
  it("#17 validateToolArguments rejects non-string for string field", () => {
    const schema = {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    };
    const valid = validateToolArguments({ path: "hello" }, schema);
    const invalid = validateToolArguments({ path: 123 }, schema);
    expect(valid.valid).toBe(true);
    expect(invalid.valid).toBe(false);
  });
});

// ===========================================================================
// 18–22: Result normalization
// ===========================================================================

describe("46.30 Security Matrix — Result normalization", () => {
  const provenance = {
    mcpServerId: "srv",
    tool: "t",
    invocationId: "inv_1",
    timestamp: Date.now(),
    authorizationTicketId: "tkt_1",
    schemaHash: "hash",
  };

  // #18: Oversized result denied when truncate=false
  it("#18 oversized non-truncatable result is denied", () => {
    const big = "x".repeat(2000);
    const result = normalizeMcpResult(big, { maxBytes: 100, truncate: false }, provenance);
    expect(result.denied).toBe(true);
  });

  // #19: Oversized result truncated when truncate=true
  it("#19 oversized result is truncated when truncate=true", () => {
    const big = "x".repeat(2000);
    const result = normalizeMcpResult(big, { maxBytes: 100, truncate: true }, provenance);
    expect(result.denied).toBe(false);
  });

  // #20: Non-JSON-serializable result denied
  it("#20 non-JSON result is denied", () => {
    const result = normalizeMcpResult(
      Symbol("nope") as unknown,
      {},
      provenance,
    );
    expect(result.denied).toBe(true);
  });

  // #21: Deep nesting beyond maxDepth denied
  it("#21 deeply nested result denied when exceeding maxDepth", () => {
    // Build a 15-level nested object
    let deep: any = { val: "leaf" };
    for (let i = 0; i < 15; i++) deep = { inner: deep };
    const result = normalizeMcpResult(deep, { maxDepth: 5 }, provenance);
    expect(result.denied).toBe(true);
  });

  // #22: Normal result passes through
  it("#22 normal small result passes normalization", () => {
    const result = normalizeMcpResult(
      { status: "ok", data: [1, 2, 3] },
      {},
      provenance,
    );
    expect(result.denied).toBe(false);
  });
});

// ===========================================================================
// 23–27: Policy engine
// ===========================================================================

describe("46.30 Security Matrix — Policy engine", () => {
  // #23: Empty policy denies everything (fail-closed)
  it("#23 empty policy denies everything", () => {
    const engine = new McpPolicyEngine();
    const result = engine.evaluate({
      capabilityName: "mcp://srv/tool",
      serverId: "srv",
      toolName: "tool",
    });
    expect(result.allowed).toBe(false);
  });

  // #24: Deny rule blocks even when preceded by allow
  it("#24 explicit deny overrides allow for same pattern", () => {
    const engine = new McpPolicyEngine({
      rules: [
        { instrument: "tool", pattern: "*", allow: true },
        { instrument: "tool", pattern: "mcp://srv/blocked_*", allow: false, reason: "blocked" },
      ],
      allowedEffectiveOperations: new Map([["read", ["mcp://*/*"]]]),
    });
    const result = engine.evaluate({
      capabilityName: "mcp://srv/blocked_tool",
      serverId: "srv",
      toolName: "blocked_tool",
      riskAdvice: { severity: "low", effectiveOperations: ["read"], riskContributions: [] },
    });
    expect(result.allowed).toBe(false);
  });

  // #25: HTTP transport denied by default
  it("#25 http transport denied by default (fail-closed transport)", () => {
    const engine = new McpPolicyEngine();
    const result = engine.evaluate({
      capabilityName: "mcp://srv/tool",
      serverId: "srv",
      toolName: "tool",
      transportKind: "http",
    });
    expect(result.allowed).toBe(false);
  });

  // #26: Unknown tenant blocked when allowlist configured
  it("#26 unknown tenant blocked when allowlist configured", () => {
    const engine = new McpPolicyEngine({
      rules: [{ instrument: "tool", pattern: "*", allow: true }],
      allowedTenants: new Set(["tenant-a"]),
      allowedEffectiveOperations: new Map([["read", ["mcp://*/*"]]]),
    });
    const result = engine.evaluate({
      capabilityName: "mcp://srv/tool",
      serverId: "srv",
      toolName: "tool",
      tenant: "tenant-b",
      riskAdvice: { severity: "low", effectiveOperations: ["read"], riskContributions: [] },
    });
    expect(result.allowed).toBe(false);
  });

  // #27: Matched deny rule includes code in evaluation result
  it("#27 deny result includes denial code", () => {
    const engine = new McpPolicyEngine();
    const result = engine.evaluate({
      capabilityName: "mcp://srv/tool",
      serverId: "srv",
      toolName: "tool",
    });
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(typeof result.code).toBe("string");
      expect(result.code.length).toBeGreaterThan(0);
    }
  });
});

// ===========================================================================
// 28–31: Credential isolation
// ===========================================================================

describe("46.30 Security Matrix — Credential isolation", () => {
  // #28: Credential stored and retrieved by scope
  it("#28 credential stored and retrieved by scope match", () => {
    const vault = new InMemoryCredentialVault();
    vault.store({
      credential: "secret-key",
      credentialClass: "read",
      serverId: "srv-1",
      toolName: "tool-a",
    });
    const found = vault.retrieve({ serverId: "srv-1", toolName: "tool-a" });
    expect(found).toBeDefined();
    expect(found!.credential).toBe("secret-key");
  });

  // #29: Credential NOT returned for wrong scope
  it("#29 credential not returned for mismatched scope", () => {
    const vault = new InMemoryCredentialVault();
    vault.store({ credential: "key", credentialClass: "read", serverId: "srv-1", toolName: "tool-a" });
    const found = vault.retrieve({ serverId: "srv-1", toolName: "tool-b" });
    expect(found).toBeUndefined();
  });

  // #30: Expired credential not returned
  it("#30 expired credential not returned by retrieve", () => {
    const vault = new InMemoryCredentialVault();
    vault.store({
      credential: "expired-key",
      credentialClass: "read",
      serverId: "srv-1",
      expiresAt: Date.now() - 10000,
    });
    const found = vault.retrieve({ serverId: "srv-1" });
    expect(found).toBeUndefined();
  });

  // #31: Revoked credential not returned
  it("#31 revoked credential not returned by retrieve", () => {
    const vault = new InMemoryCredentialVault();
    const rec = vault.store({ credential: "key", credentialClass: "read", serverId: "srv-1" });
    vault.revoke(rec.id);
    expect(vault.retrieve({ serverId: "srv-1" })).toBeUndefined();
  });
});

// ===========================================================================
// 32–35: Risk advisory
// ===========================================================================

describe("46.30 Security Matrix — Risk advisory", () => {
  // #32: Risk advisory can only RAISE severity, never lower
  it("#32 risk advisory never lowers severity below baseline", () => {
    const advisor = new McpRiskAdvisor();
    const baselines = ["low", "medium", "high", "critical"] as const;
    for (const baseline of baselines) {
      const advice = advisor.advise(baseline, undefined, { name: "read_data" });
      const rank = { low: 0, medium: 1, high: 2, critical: 3 };
      expect(rank[advice.effective]).toBeGreaterThanOrEqual(rank[baseline]);
    }
  });

  // #33: Risk advisory is advisory-only (doesn't authorize)
  it("#33 risk advisory does not contain authorization decisions", () => {
    const advisor = new McpRiskAdvisor();
    const advice = advisor.advise("medium", undefined, { name: "delete_file" });
    // McpRiskAdvice should have advisory fields, NOT allowed/denied
    expect(advice).toHaveProperty("effective");
    expect(advice).toHaveProperty("baseline");
    expect(advice).toHaveProperty("contributions");
    expect(advice).not.toHaveProperty("allowed");
    expect(advice).not.toHaveProperty("denied");
  });

  // #34: credentialClassSignal only flags admin/write (not read)
  it("#34 credentialClassSignal only flags admin and write classes", () => {
    expect(credentialClassSignal("read")).toBeUndefined();
    expect(credentialClassSignal(undefined)).toBeUndefined();
    expect(credentialClassSignal("admin")).toBeDefined();
    expect(credentialClassSignal("write")).toBeDefined();
  });

  // #35: classifyEffectiveOperations always classifies known operations
  it("#35 classifyEffectiveOperations classifies read/write/admin from names", () => {
    const readResult = classifyEffectiveOperations(undefined, { name: "get_file" });
    expect(readResult.operations).toContain("read");

    const writeResult = classifyEffectiveOperations(undefined, { name: "create_record" });
    expect(writeResult.operations).toContain("write");

    const adminResult = classifyEffectiveOperations(undefined, { name: "grant_access" });
    expect(adminResult.operations).toContain("admin");

    const destructiveResult = classifyEffectiveOperations(undefined, { name: "delete_all" });
    expect(destructiveResult.appearsIrreversible).toBe(true);
  });
});
