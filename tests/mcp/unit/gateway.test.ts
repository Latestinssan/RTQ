import { describe, expect, it, vi } from "vitest";
import {
  McpRegistry,
  McpPolicyEngine,
  McpRiskAdvisor,
  McpGateway,
  type McpServerConfig,
  type McpToolMeta,
  type McpConnection,
  type McpGatewayConfig,
} from "@rtq/mcp";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DEFAULT_SERVER: McpServerConfig = {
  serverId: "srv-1",
  name: "test-server",
  version: "1.0.0",
  transport: { kind: "in-memory", host: null },
  defaultSeverity: "medium",
};

function makeToolMeta(over: Partial<McpToolMeta> = {}): McpToolMeta {
  const name = over.name ?? "read_file";
  const description = over.description ?? "Reads a file";
  return {
    name,
    description,
    rawSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
    normalizedSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
    schemaHash: `hash_${name}`,
    protocolVersion: "2025-06-18",
    incomplete: false,
    ...over,
  };
}

function mockConnection(overrides: Record<string, unknown> = {}): McpConnection {
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

function makeGatewayConfig(overrides: Partial<McpGatewayConfig> = {}): McpGatewayConfig & { _authorizeCalls: any[]; _executeCalls: any[]; _tickets: Map<string, unknown>; _auditEvents: any[] } {
  const authorizeCalls: any[] = [];
  const executeCalls: any[] = [];
  const tickets = new Map<string, unknown>();
  const auditEvents: any[] = [];

  return {
    registry: new McpRegistry(),
    policy: new McpPolicyEngine({
      rules: [{ instrument: "tool", pattern: "*", allow: true }],
      allowedEffectiveOperations: new Map([
        ["read", ["mcp://*/*"]],
        ["write", ["mcp://*/*"]],
        ["network", ["mcp://*/*"]],
      ]),
    }),
    riskAdvisor: new McpRiskAdvisor(),
    authorize: vi.fn().mockImplementation(async (params) => {
      authorizeCalls.push(params);
      return { ticketId: `tkt_${authorizeCalls.length}`, approvalRequired: false };
    }),
    execute: vi.fn().mockImplementation(async (ticketId) => {
      executeCalls.push(ticketId);
      return { result: { ok: true } };
    }),
    tickets: {
      peek: (id: string) => tickets.get(id),
      park: (id: string, v: unknown) => { tickets.set(id, v); },
    },
    defaultLimits: { maxResultSizeBytes: 64 * 1024 },
    onAudit: (event: string, data: Record<string, unknown>) => { auditEvents.push({ event, ...data }); },
    _authorizeCalls: authorizeCalls,
    _executeCalls: executeCalls,
    _tickets: tickets,
    _auditEvents: auditEvents,
    ...overrides,
  } as any;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("McpGateway", () => {
  it("connect returns a sessionId and registers server", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    const conn = mockConnection();
    const sessionId = await gw.connect("srv-1", conn, { config: DEFAULT_SERVER });
    expect(sessionId).toMatch(/^ses_/);
    expect(gw.listSessions()).toHaveLength(1);
    expect(cfg.registry.listServers()).toHaveLength(1);
  });

  it("disconnect removes session and revokes server", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    const sessionId = await gw.connect("srv-1", conn(), { config: DEFAULT_SERVER });
    await gw.disconnect(sessionId);
    expect(gw.listSessions()).toHaveLength(0);
  });

  it("getSession returns undefined for unknown sessionId", () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    expect(gw.getSession("nonexistent")).toBeUndefined();
  });

  it("discover fetches tools from connection and registers them", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    const conn = mockConnection({
      request: vi.fn().mockResolvedValue({
        tools: [
          { name: "read_file", description: "Reads a file", inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } },
          { name: "write_file", description: "Writes a file", inputSchema: { type: "object", properties: { path: { type: "string" }, content: { type: "string" } }, required: ["path", "content"] } },
        ],
      }),
    });
    const sessionId = await gw.connect("srv-1", conn, { config: DEFAULT_SERVER });
    const tools = await gw.discover(sessionId);
    expect(tools).toHaveLength(2);
    expect(tools[0].name).toBe("read_file");
    expect(tools[1].name).toBe("write_file");
  });

  it("discover returns empty for unknown session", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    expect(await gw.discover("nonexistent")).toHaveLength(0);
  });

  it("invoke denies unknown server", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    const result = await gw.invoke("srv-unknown", "tool", {});
    expect(result.status).toBe("denied");
  });

  it("invoke denies unknown tool", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    await gw.connect("srv-1", conn(), { config: DEFAULT_SERVER });
    const result = await gw.invoke("srv-1", "nonexistent_tool", {});
    expect(result.status).toBe("denied");
  });

  it("invoke executes a valid tool through the full pipeline", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    // Connect creates session + registers server in registry
    await gw.connect("srv-1", conn(), { config: DEFAULT_SERVER });
    cfg.registry.registerTool("srv-1", makeToolMeta());

    const result = await gw.invoke("srv-1", "read_file", { path: "/tmp/test" });
    expect(result.status).toBe("executed");
    expect(cfg._authorizeCalls).toHaveLength(1);
    expect(cfg._authorizeCalls[0].capability).toBe("mcp://srv-1/read_file");
  });

  it("invoke handles authorization failure", async () => {
    const cfg = makeGatewayConfig({
      authorize: vi.fn().mockRejectedValue(new Error("no permission")),
    });
    const gw = new McpGateway(cfg);
    await gw.connect("srv-1", conn(), { config: DEFAULT_SERVER });
    cfg.registry.registerTool("srv-1", makeToolMeta());

    const result = await gw.invoke("srv-1", "read_file", { path: "/tmp/test" });
    expect(result.status).toBe("denied");
  });

  it("invoke returns approval_required when needed", async () => {
    const cfg = makeGatewayConfig({
      authorize: vi.fn().mockResolvedValue({ ticketId: "tkt_1", approvalRequired: true }),
    });
    const gw = new McpGateway(cfg);
    await gw.connect("srv-1", conn(), { config: DEFAULT_SERVER });
    cfg.registry.registerTool("srv-1", makeToolMeta());

    const result = await gw.invoke("srv-1", "read_file", { path: "/tmp/test" });
    expect(result.status).toBe("approval_required");
    expect(cfg._tickets.has("tkt_1")).toBe(true);
  });

  it("submitApproval executes when approved", async () => {
    const cfg = makeGatewayConfig({
      authorize: vi.fn().mockResolvedValue({ ticketId: "tkt_1", approvalRequired: true }),
    });
    const gw = new McpGateway(cfg);
    await gw.connect("srv-1", conn(), { config: DEFAULT_SERVER });
    cfg.registry.registerTool("srv-1", makeToolMeta());

    // First, get approval_required
    await gw.invoke("srv-1", "read_file", { path: "/tmp/test" });
    // Then submit approval
    const result = await gw.submitApproval("tkt_1", true);
    expect(result.status).toBe("executed");
  });

  it("submitApproval denies when rejected", async () => {
    const cfg = makeGatewayConfig({
      authorize: vi.fn().mockResolvedValue({ ticketId: "tkt_1", approvalRequired: true }),
    });
    const gw = new McpGateway(cfg);
    await gw.connect("srv-1", conn(), { config: DEFAULT_SERVER });
    cfg.registry.registerTool("srv-1", makeToolMeta());

    await gw.invoke("srv-1", "read_file", { path: "/tmp/test" });
    const result = await gw.submitApproval("tkt_1", false);
    expect(result.status).toBe("denied");
  });

  it("submitApproval denies unknown ticket", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    const result = await gw.submitApproval("unknown_tkt", true);
    expect(result.status).toBe("denied");
  });

  it("revokeServer removes sessions and returns tool count", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    await gw.connect("srv-1", conn(), { config: DEFAULT_SERVER });
    const count = gw.revokeServer("srv-1");
    expect(count).toBeGreaterThanOrEqual(0);
    expect(gw.listSessions()).toHaveLength(0);
  });

  it("getMetrics returns correct counts", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    await gw.connect("srv-1", conn(), { config: DEFAULT_SERVER });
    const metrics = gw.getMetrics();
    expect(metrics.connectedSessions).toBe(1);
    expect(metrics.registeredServers).toBe(1);
    expect(typeof metrics.epoch).toBe("number");
  });

  it("listTools returns tools after discover", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    const conn = mockConnection({
      request: vi.fn().mockResolvedValue({
        tools: [{ name: "tool_a", description: "Tool A", inputSchema: {} }],
      }),
    });
    const sessionId = await gw.connect("srv-1", conn, { config: DEFAULT_SERVER });
    await gw.discover(sessionId);
    expect(gw.listTools(sessionId)).toHaveLength(1);
    expect(gw.getTool(sessionId, "tool_a")).toBeDefined();
    expect(gw.getTool(sessionId, "tool_b")).toBeUndefined();
  });

  it("onAudit fires for lifecycle events", async () => {
    const cfg = makeGatewayConfig();
    const gw = new McpGateway(cfg);
    await gw.connect("srv-1", conn(), { config: DEFAULT_SERVER });
    expect(cfg._auditEvents.some((e: any) => e.event === "mcp.connected")).toBe(true);
  });

  function conn(overrides: Record<string, unknown> = {}): McpConnection {
    return mockConnection(overrides);
  }
});
