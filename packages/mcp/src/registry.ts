/**
 * MCP server + tool registry (spec 46.2, 46.5–46.8, 46.11–46.14).
 *
 * SCOPE: The registry is the RTQ-trusted record of MCP servers, their trust
 * state, and the tools/resources/prompts discovered from them. It does NOT
 * perform authorization (that is the RTQ pipeline), does NOT do transport I/O,
 * and holds no credentials (that is the McpCredentialVault). It exists so the
 * security layer has ONE provable, hashable source of truth keyed by stable
 * server id — never by a server's self-declared name.
 *
 * Integrity model (46.7, 46.8):
 *   - Every server carries a `profileHash` over its security-relevant metadata
 *     (identity, transport, auth, sandbox, tenant, owner). When the profile
 *     changes, previously issued authorizations are invalidated.
 *   - Every tool carries a `schemaHash` over its RTQ-normalized schema. A
 *     schema change bumps the tool's metaRevision and marks it incomplete until
 *     RTQ re-evaluates it; unknown tools default to denied (46.3).
 *   - A registry-wide `epoch` advances on every security-relevant change so the
 *     gateway can invalidate all bound tickets atomically.
 *
 * ALL server-declared content (names, descriptions, schemas) is UNTRUSTED.
 * RTQ builds normalized, hashed, policy-approved records from it. Server
 * severity and sandbox decisions are operator/RTQ facts, never server facts.
 */
import { canonicalStringify, sha256Hex } from "@rtq/crypto";
import type {
  McpLimits,
  McpPromptMeta,
  McpResourceMeta,
  McpResourceTemplateMeta,
  McpServerConfig,
  McpServerRecord,
  McpServerIdentity,
  McpSeverity,
  McpTrustState,
  McpToolMeta,
  McpToolRecord,
} from "./types";
import { DEFAULT_MCP_LIMITS } from "./types";

/** Legal trust-state transitions (46.5). RTQ only honors explicit, legal
 *  transitions — every other path is ignored (never silently guessed). */
const LEGAL_TRUST_TRANSITIONS: Readonly<
  Record<McpTrustState, readonly McpTrustState[]>
> = {
  unknown: ["pending", "approved", "restricted", "revoked", "blocked"],
  pending: ["approved", "restricted", "revoked", "blocked"],
  approved: ["pending", "restricted", "revoked", "blocked"],
  restricted: ["pending", "approved", "revoked", "blocked"],
  revoked: ["pending"],
  blocked: [],
};

export type McpRegistryEvent =
  | { kind: "server_registered"; serverId: string; epoch: number }
  | { kind: "server_updated"; serverId: string; epoch: number }
  | {
      kind: "server_trust_changed";
      serverId: string;
      from: McpTrustState;
      to: McpTrustState;
      epoch: number;
    }
  | {
      kind: "tool_registered";
      serverId: string;
      toolName: string;
      epoch: number;
    }
  | { kind: "tool_updated"; serverId: string; toolName: string; epoch: number };

/**
 * Hash of a server's security-relevant profile. This is what ticket bindings
 * and re-approval decisions are anchored to (46.7). Only operator/RTQ-decided
 * facts are included — server-declared names/descriptions are NOT.
 */
export function serverProfileHash(
  identity: McpServerIdentity,
  extended: {
    sandbox?: string | null;
    sandboxRequired?: boolean;
    auth?: string | null;
    environment?: string;
    tenant?: string;
    owner?: string;
    policyScopeId?: string;
  } = {},
): string {
  return sha256Hex(
    canonicalStringify({
      stableId: identity.stableId,
      name: identity.name,
      version: identity.version,
      transport: identity.transport,
      endpoint: identity.endpoint ?? null,
      authMethod: identity.authMethod ?? null,
      identityMaterial: identity.identityMaterial ?? null,
      identityVerified: identity.identityVerified,
      sandbox: extended.sandbox ?? null,
      sandboxRequired: Boolean(extended.sandboxRequired),
      auth: extended.auth ?? null,
      environment: extended.environment ?? null,
      tenant: extended.tenant ?? null,
      owner: extended.owner ?? null,
      policyScopeId: extended.policyScopeId ?? null,
    }),
  );
}

function serverRecordFromConfig(config: McpServerConfig): McpServerRecord {
  const identity: McpServerIdentity = {
    stableId: config.serverId,
    name: config.name ?? config.serverId,
    version: config.version ?? "0.0.0",
    transport: config.transport.kind,
    endpoint: config.transport.kind === "http" ? config.transport.url : null,
    authMethod: config.auth?.method ?? null,
    identityMaterial: config.identityMaterial ?? null,
    identityVerified: false,
  };
  const now = Date.now();
  const sandbox = config.sandbox;
  return {
    serverId: config.serverId,
    trustState: config.initialTrust ?? "pending",
    identity,
    defaultSeverity: config.defaultSeverity ?? "medium",
    toolSeverity: new Map(Object.entries(config.toolSeverity ?? {})),
    sandbox: sandbox,
    sandboxRequired: config.sandboxRequired ?? false,
    auth: config.auth ?? null,
    environment: config.environment,
    tenant: config.tenant,
    owner: config.owner,
    policyScopeId: config.policyScopeId ?? config.serverId,
    registeredAt: now,
    lastVerifiedAt: now,
    profileHash: serverProfileHash(identity, {
      sandbox: sandbox ? canonicalStringify(sandbox) : null,
      sandboxRequired: config.sandboxRequired,
      auth: config.auth?.method ?? null,
      environment: config.environment,
      tenant: config.tenant,
      owner: config.owner,
      policyScopeId: config.policyScopeId,
    }),
    needsReapproval: (config.initialTrust ?? "pending") !== "approved",
    tools: new Map(),
    resources: [],
    resourceTemplates: [],
    prompts: [],
    protocolVersion: "",
    connection: { connected: false },
  };
}

function toolRecordFromMeta(
  serverId: string,
  meta: McpToolMeta,
  severity: McpSeverity,
  epoch: number,
): McpToolRecord {
  return {
    serverId,
    name: meta.name,
    description: meta.description,
    schemaHash: meta.schemaHash,
    metaRevision: 1,
    normalizedSchema: meta.normalizedSchema,
    severity,
    capabilityName: `mcp://${serverId}/${meta.name}`,
    capabilityVersion: 1,
    incomplete: meta.incomplete,
    registered: false,
    needsReevaluation: meta.incomplete,
    declaredCapabilities: meta.declaredCapabilities,
    registryEpoch: epoch,
  };
}

/**
 * In-memory server + tool registry.
 *
 * Design rules (46.2, 46.46):
 *   - Registration defaults to denied. A server whose trust is `revoked` or
 *     `blocked` is never asked to execute anything.
 *   - Tool discovery is lazy and UNTRUSTED. Tools only become executable after
 *     the gateway explicitly registers them via `registerTool` (which RTQ does
 *     only after policy approval).
 *   - Every security-relevant change bumps BOTH the server-level revision and
 *     the registry `epoch`, so the gateway can invalidate all tickets that were
 *     bound to the previous state (46.8, 46.30 #4).
 *   - `registerTool` is idempotent: re-registering the same name+schemaHash
 *     leaves revision and epoch unchanged (no spurious invalidation).
 */
export class McpRegistry {
  private readonly servers = new Map<string, McpServerRecord>();
  private epoch = 0;

  /** @internal — wired by the gateway to invalidate RTQ tickets. */
  onChange?: (event: McpRegistryEvent) => void;

  constructor(private readonly limits: McpLimits = {}) {}

  getLimits(): McpLimits {
    return this.limits;
  }

  registerServer(config: McpServerConfig): McpServerRecord {
    const existing = this.updateServer(config);
    if (existing) return existing;
    const record = serverRecordFromConfig(config);
    this.servers.set(config.serverId, record);
    this.bump();
    this.onChange?.({
      kind: "server_registered",
      serverId: record.serverId,
      epoch: this.epoch,
    });
    return record;
  }

  updateServer(config: McpServerConfig): McpServerRecord | undefined {
    const existing = this.servers.get(config.serverId);
    if (!existing) return undefined;
    const next = serverRecordFromConfig(config);
    const profileChanged =
      existing.profileHash !== next.profileHash ||
      existing.identity.identityMaterial !== next.identity.identityMaterial;
    if (!profileChanged) {
      // Keep the trusted tool/resources/prompt state because the security
      // profile is unchanged — no unintended invalidation.
      next.tools = existing.tools;
      next.resources = existing.resources;
      next.resourceTemplates = existing.resourceTemplates;
      next.prompts = existing.prompts;
      next.connection = existing.connection;
    } else {
      next.needsReapproval = true;
    }
    next.registeredAt = existing.registeredAt;
    this.servers.set(config.serverId, next);
    if (profileChanged) {
      this.bump();
      this.onChange?.({
        kind: "server_updated",
        serverId: config.serverId,
        epoch: this.epoch,
      });
    }
    return next;
  }

  /**
   * Transition a server's trust state. Only legal + real transitions advance
   * the epoch (46.5); everything else is a no-op so an accidental call cannot
   * burn live tickets.
   */
  setTrustState(
    serverId: string,
    to: McpTrustState,
  ): { ok: boolean; reason?: string } {
    const record = this.servers.get(serverId);
    if (!record) return { ok: false, reason: "unknown_server" };
    const from = record.trustState;
    if (from === to) return { ok: true };
    if (!LEGAL_TRUST_TRANSITIONS[from]?.includes(to)) {
      return { ok: false, reason: `illegal_transition:${from}->${to}` };
    }
    record.trustState = to;
    this.bump(); // trust transitions always invalidate bound tickets (46.8)
    this.onChange?.({
      kind: "server_trust_changed",
      serverId,
      from,
      to,
      epoch: this.epoch,
    });
    return { ok: true };
  }

  /**
   * Register (or re-evaluate) a discovered tool. Returns the tool record.
   * When the tool already exists with a DIFFERENT schemaHash, its metaRevision
   * is bumped and it is marked incomplete — RTQ invalidates the prior binding
   * and it fails closed until re-registered.
   */
  registerTool(serverId: string, meta: McpToolMeta): McpToolRecord {
    const record = this.servers.get(serverId);
    if (!record) {
      throw new Error(
        `MCP: unknown server "${serverId}" — register the server first`,
      );
    }
    const existing = record.tools.get(meta.name);
    if (existing && existing.schemaHash === meta.schemaHash) {
      return existing; // idempotent — no epoch bump, no ticket invalidation
    }
    const severity =
      record.toolSeverity.get(meta.name) ?? record.defaultSeverity;
    const tool = toolRecordFromMeta(serverId, meta, severity, this.epoch);
    tool.metaRevision = existing ? existing.metaRevision + 1 : 1;
    const tools = new Map(record.tools);
    tools.set(meta.name, tool);
    record.tools = tools;
    this.bump();
    this.onChange?.(
      existing
        ? {
            kind: "tool_updated",
            serverId,
            toolName: meta.name,
            epoch: this.epoch,
          }
        : {
            kind: "tool_registered",
            serverId,
            toolName: meta.name,
            epoch: this.epoch,
          },
    );
    return tool;
  }

  /**
   * Operator/RTQ registration: make a discovered tool executable. This is the
   * ONLY transition that sets `registered` true and clears `registered`-gated
   * incompleteness. The gateway calls this only after policy approval.
   */
  registerToolAsExecutable(
    serverId: string,
    toolName: string,
  ): McpToolRecord | undefined {
    const record = this.servers.get(serverId);
    const tool = record?.tools.get(toolName);
    if (!record || !tool) return undefined;
    tool.registered = true;
    tool.registeredAt = Date.now();
    tool.needsReevaluation = false;
    this.bump();
    return tool;
  }

  /** Revoke a server and return the number of tools it had registered. */
  revokeServer(serverId: string): number {
    const record = this.servers.get(serverId);
    if (!record) return 0;
    this.setTrustState(serverId, "revoked");
    return record.tools.size;
  }

  listServers(): readonly McpServerRecord[] {
    return [...this.servers.values()];
  }

  getServer(serverId: string): McpServerRecord | undefined {
    return this.servers.get(serverId);
  }

  listTools(serverId: string): readonly McpToolRecord[] {
    return this.servers.get(serverId)
      ? [...this.servers.get(serverId)!.tools.values()]
      : [];
  }

  getTool(serverId: string, toolName: string): McpToolRecord | undefined {
    return this.servers.get(serverId)?.tools.get(toolName);
  }

  /** Current registry epoch — bumped on every security-relevant change. */
  getEpoch(): number {
    return this.epoch;
  }

  private bump(): void {
    this.epoch += 1;
  }
}
