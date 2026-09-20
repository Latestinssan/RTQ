/**
 * RTQ MCP gateway (spec 46.28–46.33).
 * MCP is an INTEGRATION layer, NEVER an authorization boundary (46.31, 46.38).
 * Fail closed: unknown servers → denied; unregistered tools → denied;
 * unclassified operations → denied; oversized results → denied.
 * Risk advisories can only RAISE severity, never authorize (46.14, 46.28 #2).
 */
import type {
  McpLimits,
  McpOriginKind,
  McpResultProvenance,
  McpSecurityContext,
  McpServerConfig,
  McpServerRecord,
  McpSeverity,
  McpToolMeta,
  McpToolRecord,
  McpTrustState,
} from "./types";
import { McpRegistry } from "./registry";
import { McpPolicyEngine } from "./policy";
import { McpRiskAdvisor, classifyEffectiveOperations } from "./risk";
import type { McpRiskAdvice, McpEffectiveOperation } from "./risk";
import {
  computeToolSchemaHash,
  normalizeToolSchema,
  validateToolArguments,
} from "./schemas";
import { normalizeMcpResult } from "./results";
import type { McpConnection } from "./transports";

// ---------------------------------------------------------------------------
// Gateway-local types
// ---------------------------------------------------------------------------

/** Gateway-level invoke result (simpler than the RTQ-level McpGatewayResult). */
export type McpGatewayResult =
  | { status: "executed"; ticketId: string; result: unknown }
  | { status: "approval_required"; ticketId: string }
  | { status: "denied"; reason: string };

/** Single-use ticket bindings (46.30). */
export interface McpTicketBindings {
  serverId: string;
  toolName: string;
  schemaHash: string;
  argumentsHash: string;
  effectiveOperations: readonly McpEffectiveOperation[];
}

/** Per-connection session state. */
export interface McpServerSession {
  sessionId: string;
  serverId: string;
  connection: McpConnection;
  record: McpServerRecord;
  tools: McpToolRecord[];
  protocolVersion: string;
  connectedAt: number;
  limits: McpLimits;
}

/** Gateway configuration — all external surfaces injected, never imported. */
export interface McpGatewayConfig {
  registry: McpRegistry;
  policy: McpPolicyEngine;
  riskAdvisor: McpRiskAdvisor;
  /** RTQ authorize callback. */
  authorize: (params: {
    capability: string;
    version: string;
    input: Record<string, unknown>;
    origin?: McpOriginKind;
    metadata?: { mcp?: McpTicketBindings };
  }) => Promise<{ ticketId: string; approvalRequired?: boolean }>;
  /** RTQ execute callback. */
  execute: (ticketId: string) => Promise<{ result: unknown; risk?: string }>;
  /** Ticket store — gateway parks approval_required tickets here. */
  tickets: { peek(id: string): unknown; park(id: string, v: unknown): void };
  defaultLimits?: McpLimits;
  securityContext?: McpSecurityContext;
  onAudit?: (event: string, data: Record<string, unknown>) => void;
}

// ---------------------------------------------------------------------------
// McpGateway
// ---------------------------------------------------------------------------

let _seq = 0;

export class McpGateway {
  private readonly config: McpGatewayConfig;
  private readonly sessions = new Map<string, McpServerSession>();

  constructor(config: McpGatewayConfig) {
    this.config = config;
    // Wire registry onChange → audit (46.8 epoch bump invalidates tickets).
    config.registry.onChange = (event) => {
      config.onAudit?.("mcp.registry.event", event as Record<string, unknown>);
    };
  }

  // -- Connection lifecycle ------------------------------------------------

  /**
   * Connect to an MCP server: handshake, register in registry, store session.
   * Fail closed on any error (46.3, 46.17).
   */
  async connect(
    serverId: string,
    connection: McpConnection,
    opts?: { config?: McpServerConfig; protocolVersion?: string },
  ): Promise<string> {
    const sessionId = `ses_${++_seq}_${Date.now().toString(36)}`;
    const protocolVersion = opts?.protocolVersion ?? "2025-06-18";

    // Register the server with the RTQ registry (fail-closed, 46.5).
    const serverConfig: McpServerConfig = {
      serverId,
      transport: { kind: "in-memory" as const, host: null },
      ...opts?.config,
    };
    const record = this.config.registry.registerServer(serverConfig);

    const session: McpServerSession = {
      sessionId,
      serverId,
      connection,
      record,
      tools: [],
      protocolVersion,
      connectedAt: Date.now(),
      limits: { ...this.config.defaultLimits },
    };
    this.sessions.set(sessionId, session);
    this.config.onAudit?.("mcp.connected", { serverId, sessionId });
    return sessionId;
  }

  /** Disconnect: revoke session, invalidate bound tickets (46.8, 46.30). */
  async disconnect(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.config.registry.revokeServer(session.serverId);
    this.sessions.delete(sessionId);
    this.config.onAudit?.("mcp.disconnected", {
      serverId: session.serverId,
      sessionId,
    });
  }

  getSession(sessionId: string): McpServerSession | undefined {
    return this.sessions.get(sessionId);
  }

  listSessions(): readonly McpServerSession[] {
    return [...this.sessions.values()];
  }

  // -- Tool discovery (46.2, 46.3, 46.4) -----------------------------------

  /**
   * Discover tools from a connected server. All discovered tools are UNTRUSTED
   * metadata; RTQ normalizes schemas, computes hashes, and registers them in
   * the registry (fail-closed: unknown tools denied, 46.3, 46.5).
   */
  async discover(sessionId: string): Promise<McpToolRecord[]> {
    const session = this.sessions.get(sessionId);
    if (!session) return [];

    let rawTools: unknown;
    try {
      rawTools = await session.connection.request(
        "tools/list",
        {},
        { timeoutMs: 30_000 },
      );
    } catch {
      this.config.onAudit?.("mcp.discover.failed", {
        serverId: session.serverId,
      });
      return [];
    }

    const items: unknown[] = Array.isArray(rawTools)
      ? rawTools
      : Array.isArray((rawTools as Record<string, unknown>)?.tools)
        ? ((rawTools as Record<string, unknown>).tools as unknown[])
        : [];

    const tools: McpToolRecord[] = [];
    for (const item of items) {
      if (!isRecord(item)) continue;
      const name = typeof item.name === "string" ? item.name : "";
      if (!name) continue;
      const description =
        typeof item.description === "string" ? item.description : "";
      const rawSchema = isRecord(item.inputSchema)
        ? (item.inputSchema as Record<string, unknown>)
        : {};
      const normalizedResult = normalizeToolSchema(rawSchema);
      const normalizedSchema = normalizedResult.schema;
      const schemaHash = computeToolSchemaHash({
        name,
        description,
        normalizedSchema,
      });
      const meta: McpToolMeta = {
        name,
        description,
        rawSchema,
        normalizedSchema,
        schemaHash,
        protocolVersion: session.protocolVersion,
        incomplete: normalizedResult.incomplete,
      };
      try {
        const record = this.config.registry.registerTool(
          session.serverId,
          meta,
        );
        tools.push(record);
      } catch {
        /* tool registration failed — skip (fail-closed: unregistered tools
         * are denied at invoke time, 46.5). */
      }
    }
    session.tools = tools;
    this.config.onAudit?.("mcp.discovered", {
      serverId: session.serverId,
      toolCount: tools.length,
    });
    return tools;
  }

  listTools(sessionId: string): readonly McpToolRecord[] {
    return this.sessions.get(sessionId)?.tools ?? [];
  }

  getTool(sessionId: string, toolName: string): McpToolRecord | undefined {
    const session = this.sessions.get(sessionId);
    return session
      ? this.config.registry.getTool(session.serverId, toolName)
      : undefined;
  }

  // -- Invocation pipeline (46.28–46.31) -----------------------------------

  /**
   * Invoke an MCP tool through the full RTQ pipeline:
   *  1. Validate args against RTQ-normalized schema.
   *  2. Classify effective operations (46.24–46.25).
   *  3. Risk advisor produces advisory severity (raise-only, 46.14, 46.28 #2).
   *  4. Policy engine evaluates (fail-closed: absent policy = deny, 46.9).
   *  5. RTQ authorize → ticket (single-use, non-replayable, 46.28, 46.30).
   *  6. Execute ticket → result → normalize (46.12, max size/depth).
   *  7. Return McpGatewayResult (executed | approval_required | denied).
   */
  async invoke(
    serverId: string,
    toolName: string,
    args: Record<string, unknown>,
    opts?: {
      origin?: McpOriginKind;
      tenant?: string;
      ctx?: McpSecurityContext;
    },
  ): Promise<McpGatewayResult> {
    // 1. Find session and tool record (46.3 unknown server, 46.5 unknown tool).
    const session = this.findSession(serverId);
    if (!session) {
      return { status: "denied", reason: `unknown server: ${serverId}` };
    }
    const tool = this.config.registry.getTool(serverId, toolName);
    if (!tool) {
      return { status: "denied", reason: `unknown tool: ${toolName}` };
    }

    // 2. Validate input against RTQ-normalized schema (46.30 #6).
    const validation = validateToolArguments(args, tool.normalizedSchema);
    if (!validation.valid) {
      return {
        status: "denied",
        reason: `input validation failed: ${validation.errors.join("; ")}`,
      };
    }

    // 3. Classify effective operations (46.24–46.25).
    const classified = classifyEffectiveOperations(
      opts?.ctx ?? this.config.securityContext,
      { name: tool.name, description: tool.description },
      session.record.identity.transport,
    );

    // 4. Risk advisory (raise-only, 46.14, 46.25, 46.28 #2).
    const riskAdvice = this.config.riskAdvisor.advise(
      tool.severity,
      opts?.ctx ?? this.config.securityContext,
      { name: tool.name, description: tool.description },
      { identityVerified: session.record.identity.identityVerified },
    );

    // 5. Policy evaluation (fail-closed: absent policy = deny, 46.9).
    const policyResult = this.config.policy.evaluate({
      capabilityName: tool.capabilityName,
      serverId,
      toolName,
      severity: tool.severity,
      origin: opts?.origin,
      tenant: opts?.tenant,
      riskAdvice,
      ctx: opts?.ctx ?? this.config.securityContext,
      limits: session.limits,
      identityVerified: session.record.identity.identityVerified,
    });
    if (!policyResult.allowed) {
      this.config.onAudit?.("mcp.policy.denied", {
        serverId,
        toolName,
        reason: policyResult.reason,
      });
      return { status: "denied", reason: policyResult.reason };
    }

    // 6. Compute argument hash for idempotency (46.20) + ticket bindings.
    const argumentsHash = simpleHash(JSON.stringify(args));
    const bindings: McpTicketBindings = {
      serverId,
      toolName,
      schemaHash: tool.schemaHash,
      argumentsHash,
      effectiveOperations: classified.operations,
    };

    // 7. RTQ authorize (single-use ticket, 46.28, 46.30).
    let authResult: { ticketId: string; approvalRequired?: boolean };
    try {
      authResult = await this.config.authorize({
        capability: tool.capabilityName,
        version: String(tool.capabilityVersion),
        input: args,
        origin: opts?.origin,
        metadata: { mcp: bindings },
      });
    } catch (err) {
      return {
        status: "denied",
        reason: `authorization failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    // 8. Approval required? Park ticket, return approval_required (46.19).
    if (authResult.approvalRequired) {
      this.config.tickets.park(authResult.ticketId, bindings);
      return {
        status: "approval_required",
        ticketId: authResult.ticketId,
      } as McpGatewayResult;
    }

    // 9. Execute the ticket (single-use, non-replayable, 46.28, 46.30).
    return this.executeTicket(authResult.ticketId, session, tool, args);
  }

  // -- Approval flow (46.19) -----------------------------------------------

  /**
   * Submit a user's approval decision for a parked ticket. If approved,
   * executes the ticket; if denied, removes it from the park.
   */
  async submitApproval(
    ticketId: string,
    approved: boolean,
  ): Promise<McpGatewayResult> {
    const bindings = this.config.tickets.peek(ticketId);
    if (!bindings || !isMcpTicketBindings(bindings)) {
      return { status: "denied", reason: `unknown ticket: ${ticketId}` };
    }
    if (!approved) {
      this.config.onAudit?.("mcp.approval.denied", { ticketId });
      return { status: "denied", reason: "user denied the invocation" };
    }

    const session = this.findSession(bindings.serverId);
    if (!session) {
      return {
        status: "denied",
        reason: `server ${bindings.serverId} disconnected`,
      };
    }
    const tool = this.config.registry.getTool(
      bindings.serverId,
      bindings.toolName,
    );
    if (!tool) {
      return { status: "denied", reason: `tool ${bindings.toolName} removed` };
    }

    return this.executeTicket(ticketId, session, tool, {});
  }

  // -- Execution (46.28, 46.30) -------------------------------------------

  /** Execute an approved ticket against the server, normalize result. */
  private async executeTicket(
    ticketId: string,
    session: McpServerSession,
    tool: McpToolRecord,
    args: Record<string, unknown>,
  ): Promise<McpGatewayResult> {
    try {
      // Call the MCP tool via the connection transport.
      const rawResult = await session.connection.request(
        "tools/call",
        {
          name: tool.name,
          arguments: args,
        },
        { timeoutMs: session.limits.requestTimeoutMs ?? 30_000 },
      );

      // Build provenance (46.12).
      const provenance: McpResultProvenance = {
        mcpServerId: session.serverId,
        tool: tool.name,
        invocationId: `inv_${++_seq}`,
        timestamp: Date.now(),
        authorizationTicketId: ticketId,
        schemaHash: tool.schemaHash,
      };

      // Normalize result — enforces max size/depth (46.30 #6).
      const maxResultBytes =
        session.limits.maxResultSizeBytes ??
        this.config.defaultLimits?.maxResultSizeBytes ??
        1024 * 1024;
      const normalized = normalizeMcpResult(
        rawResult,
        {
          maxBytes: maxResultBytes,
          truncate: session.limits.truncateOversizedResults ?? false,
        },
        provenance,
      );

      if (normalized.denied) {
        return { status: "denied", reason: normalized.reason };
      }

      // Consume the ticket via RTQ execute.
      await this.config.execute(ticketId);

      this.config.onAudit?.("mcp.executed", {
        serverId: session.serverId,
        toolName: tool.name,
        ticketId,
      });

      return {
        status: "executed",
        ticketId,
        result: normalized.result,
      } as McpGatewayResult;
    } catch (err) {
      return {
        status: "denied",
        reason: `execution failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  // -- Admin ----------------------------------------------------------------

  /** Revoke a server: disconnects all sessions, invalidates all tickets. */
  revokeServer(serverId: string): number {
    const revoked = this.config.registry.revokeServer(serverId);
    for (const [sid, session] of this.sessions) {
      if (session.serverId === serverId) this.sessions.delete(sid);
    }
    this.config.onAudit?.("mcp.server.revoked", {
      serverId,
      toolsRevoked: revoked,
    });
    return revoked;
  }

  getMetrics(): {
    connectedSessions: number;
    registeredServers: number;
    registeredTools: number;
    epoch: number;
  } {
    return {
      connectedSessions: this.sessions.size,
      registeredServers: this.config.registry.listServers().length,
      registeredTools: [...this.sessions.values()].reduce(
        (n, s) => n + s.tools.length,
        0,
      ),
      epoch: this.config.registry.getEpoch(),
    };
  }

  // -- Private helpers -----------------------------------------------------

  private findSession(serverId: string): McpServerSession | undefined {
    for (const session of this.sessions.values()) {
      if (session.serverId === serverId) return session;
    }
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Internal utilities
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isMcpTicketBindings(v: unknown): v is McpTicketBindings {
  if (!isRecord(v)) return false;
  return (
    typeof v.serverId === "string" &&
    typeof v.toolName === "string" &&
    typeof v.schemaHash === "string" &&
    typeof v.argumentsHash === "string"
  );
}

/** Non-cryptographic hash for internal argument fingerprinting (46.20). */
function simpleHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0;
  }
  return Math.abs(hash).toString(36);
}
