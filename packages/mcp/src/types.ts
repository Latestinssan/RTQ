/**
 * RTQ MCP integration domain types (spec section 46).
 *
 * SECURITY INVARIANT: everything typed here that originates from an MCP server
 * (tool metadata, schemas, descriptions, resources, prompts) is UNTRUSTED
 * unless explicitly authenticated AND authorized by RTQ. The trusted surface is
 * the `McpServerRecord` registry state and the `McpToolRecord` that RTQ builds
 * from normalized + policy-approved data.
 */
import type { ApprovalStrategy, RiskLevel } from "@rtq/core";
import type { SandboxSpec } from "@rtq/sandbox";

/** MCP transport families supported by this layer. */
export type McpTransportKind = "in-memory" | "stdio" | "http";

/** Server trust state (spec 46.6). */
export type McpTrustState =
  "unknown" | "pending" | "approved" | "restricted" | "revoked" | "blocked";

/** Operator-declared severity class used as the risk baseline. */
export type McpSeverity = "low" | "medium" | "high" | "critical";

/** Verified context in which an RTQ operator/registry operation runs. This is
 *  RTQ-side provenance (46.6), never server-declared data. */
export interface McpSecurityContext {
  /** RTQ operator/principal performing the operation. */
  actor: string;
  tenant?: string;
  environment?: string;
}

export interface McpServerIdentity {
  /** Stable RTQ-assigned server id (never the server's self-declared name). */
  stableId: string;
  /** Server-declared name (UNTRUSTED display only). */
  name: string;
  /** Server-declared version (UNTRUSTED; RTQ tracks its own registration). */
  version: string;
  transport: McpTransportKind;
  endpoint: string | null;
  authMethod: string | null;
  /** Verified identity material fingerprint (e.g. TLS certificate SHA-256),
   *  or null when identity could not be independently verified. */
  identityMaterial: string | null;
  identityVerified: boolean;
}

/** Tool metadata — all server-originated fields are UNTRUSTED. */
export interface McpToolMeta {
  name: string;
  /** Server-provided description (UNTRUSTED — never an authorization input). */
  description: string;
  /** Raw server-provided JSON Schema (UNTRUSTED). */
  rawSchema: Record<string, unknown>;
  /** RTQ-normalized, hardened schema (trusted: built by RTQ). */
  normalizedSchema: Record<string, unknown>;
  /** SHA-256 of canonical { name, description, normalizedSchema, declaredCapabilities }. */
  schemaHash: string;
  /** MCP protocol version announced when this tool was discovered. */
  protocolVersion: string;
  declaredCapabilities?: readonly string[];
  /** True when the raw schema contained constructs RTQ could not fully
   *  normalize (e.g. $ref). Such tools fail closed unless explicitly approved. */
  incomplete: boolean;
}

export interface McpResourceMeta {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
  sizeHint?: number;
}

export interface McpResourceTemplateMeta {
  uriTemplate: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface McpPromptMeta {
  name: string;
  description?: string;
  arguments?: readonly {
    name: string;
    description?: string;
    required?: boolean;
  }[];
}

/** In-memory config: wire to an embedded McpServerHost directly. */
export interface McpInMemoryConfig {
  kind: "in-memory";
  host: unknown; // McpServerHost (imported structurally to avoid cycles in configs)
}

/** Local process config. May be sandboxed per McpServerConfig.sandbox. */
export interface McpStdioConfig {
  kind: "stdio";
  command: string;
  args?: readonly string[];
  cwd?: string;
  env?: Record<string, string>;
}

/** Remote streamable-HTTP config (TLS when https). */
export interface McpHttpConfig {
  kind: "http";
  url: string;
  headers?: Record<string, string>;
  /** TLS verification (default: require valid certificates). */
  tls?: { rejectUnauthorized?: boolean };
}

export type McpTransportConfig =
  McpInMemoryConfig | McpStdioConfig | McpHttpConfig;

export interface McpAuthConfig {
  method: "api_key" | "bearer" | "mtls" | "signed" | "oauth" | "none";
  /** Reference into the McpCredentialVault; never an inline secret. */
  credentialRef?: string;
}

export interface McpServerConfig {
  serverId: string;
  /** Default trust state on registration (default 'pending'). */
  initialTrust?: McpTrustState;
  name?: string;
  version?: string;
  transport: McpTransportConfig;
  auth?: McpAuthConfig | null;
  /** Operator-declared default severity for unclassified tools. */
  defaultSeverity?: McpSeverity;
  /** Per-tool severity overrides (operator-declared). */
  toolSeverity?: Record<string, McpSeverity>;
  /** OS sandbox spec for locally executed (stdio) servers (spec 46.16). */
  sandbox?: SandboxSpec;
  /** Fail closed when the OS sandbox cannot be constructed. */
  sandboxRequired?: boolean;
  /** Server identity fingerprint RTQ verified during registration. */
  identityMaterial?: string | null;
  environment?: string;
  tenant?: string;
  owner?: string;
  policyScopeId?: string;
}

/** Recorded server state (RTQ-trusted). */
export interface McpServerRecord {
  serverId: string;
  trustState: McpTrustState;
  identity: McpServerIdentity;
  defaultSeverity: McpSeverity;
  toolSeverity: ReadonlyMap<string, McpSeverity>;
  sandbox?: SandboxSpec;
  sandboxRequired: boolean;
  auth?: McpAuthConfig | null;
  environment?: string;
  tenant?: string;
  owner?: string;
  policyScopeId?: string;
  /** Registered timestamp / last verification / revocation. */
  registeredAt: number;
  lastVerifiedAt: number;
  revokedAt?: number;
  revocationReason?: string;
  /** Hash of security-relevant server metadata; changes force re-verification
   *  (spec 46.7). */
  profileHash: string;
  needsReapproval: boolean;
  /** Tool records keyed by tool name. */
  tools: ReadonlyMap<string, McpToolRecord>;
  /** Resource metadata (untrusted content until read+policy approved). */
  resources: readonly McpResourceMeta[];
  resourceTemplates: readonly McpResourceTemplateMeta[];
  /** Prompt metadata (untrusted instructions). */
  prompts: readonly McpPromptMeta[];
  protocolVersion: string;
  connection: McpConnectionState;
}

export interface McpConnectionState {
  connected: boolean;
  lastConnectedAt?: number;
  lastError?: string;
  connectedAt?: number;
  /** Enforcement report when the local server runs inside an OS sandbox. */
  enforcement?: {
    backend: string;
    verified: boolean;
    isolation: {
      filesystem: boolean;
      network: boolean;
      process: boolean;
      environment: boolean;
    };
  };
}

/** RTQ-trusted per-tool registration state. */
export interface McpToolRecord {
  serverId: string;
  name: string;
  description: string;
  schemaHash: string;
  /** Security-relevant change detector: bumped when any bound metadata changes. */
  metaRevision: number;
  normalizedSchema: Record<string, unknown>;
  severity: McpSeverity;
  /** RTQ capability name: `mcp://<serverId>/<toolName>`. */
  capabilityName: string;
  capabilityVersion: number;
  incomplete: boolean;
  /** True until an operator/policy explicitly registers the tool. Registration
   *  is REQUIRED before execution (spec 46.3: unknown tools default to denied). */
  registered: boolean;
  registeredAt?: number;
  /** Set when the tool was previously approved and its bound metadata changed
   *  (spec 46.7): affected authorization state was invalidated. */
  needsReevaluation: boolean;
  declaredCapabilities?: readonly string[];
  registryEpoch: number;
}

/** Operational limits (spec 46.21). Every limit is enforceable. */
export interface McpLimits {
  /** Connection establishment timeout (ms). */
  connectTimeoutMs?: number;
  /** Per-request timeout (ms), clamped by policy maxExecutionDurationMs. */
  requestTimeoutMs?: number;
  /** Approval timeout (ms) — inherited from RTQ challenge TTL. */
  approvalTimeoutMs?: number;
  /** Maximum serialized input size (bytes). */
  maxInputSizeBytes?: number;
  /** Maximum serialized result size (bytes). Denied when exceeded (spec
   *  46.30 #6) unless `truncateOversizedResults` is set. */
  maxResultSizeBytes?: number;
  /** When true, oversized results are truncated instead of denied. */
  truncateOversizedResults?: boolean;
  /** Maximum nested depth for inputs and results. */
  maxDepth?: number;
  /** Maximum concurrent in-flight calls per server. */
  maxConcurrentPerServer?: number;
  /** Per-server rate limit (calls per window). */
  serverRateLimit?: { calls: number; windowMs: number };
  /** Per-tool rate limit (calls per window). */
  toolRateLimit?: { calls: number; windowMs: number };
}

export const DEFAULT_MCP_LIMITS: Required<
  Pick<
    McpLimits,
    | "connectTimeoutMs"
    | "requestTimeoutMs"
    | "maxInputSizeBytes"
    | "maxResultSizeBytes"
    | "maxDepth"
  >
> = {
  connectTimeoutMs: 10_000,
  requestTimeoutMs: 30_000,
  maxInputSizeBytes: 256 * 1024,
  maxResultSizeBytes: 1 * 1024 * 1024,
  maxDepth: 12,
};

/** Credential classes (46.15). */
export type McpCredentialClass = "read" | "write" | "admin";

/** A resolved credential — MUST never enter model context, tool descriptions,
 *  audit logs or sandboxed processes (unless explicitly policy-authorized). */
export interface McpCredential {
  id: string;
  class: McpCredentialClass;
  auth: Record<string, string>;
  /** Set when the credential is being used after rotation/revocation. */
  revoked?: boolean;
}

/** Scoping tuple for credential access (46.15). */
export interface McpCredentialScope {
  agent: string;
  serverId: string;
  toolName?: string;
  tenant?: string;
  environment?: string;
  resourceScope?: string;
}

/** Where the operation originates (policy distinguishes these, 46.39). */
export type McpOriginKind =
  | "direct_user"
  | "agent"
  | "browser_agent"
  | "automation"
  | "mcp_server"
  | "remote_device"
  | "plugin"
  | "unknown";

/** Provenance attached to every MCP result (46.12). */
export interface McpResultProvenance {
  mcpServerId: string;
  tool: string;
  invocationId: string;
  timestamp: number;
  authorizationTicketId: string;
  schemaHash: string;
}

/** Result of normalizing an MCP tool/resource result. */
export interface McpNormalizedResult {
  data: unknown;
  provenance: McpResultProvenance;
  /** Flags are advisory data — never authorization. */
  flags: McpQualityFlags;
}

export type McpPolicyEvaluation =
  | { allowed: true; reason: string; matched: string[] }
  | { allowed: false; reason: string; code: string; matched: string[] };

export interface McpInvokeRequest {
  serverId: string;
  tool: string;
  arguments: Record<string, unknown>;
  actor?: string;
  agent?: string;
  origin?: McpOriginKind;
  tenant?: string;
  workspace?: string;
  resourceScope?: string;
  environment?: string;
  /** Idempotency key: retries with the same key never re-execute (46.20). */
  idempotencyKey?: string;
  /** Claimed AI model/provider. NEVER changes the authorization boundary
   *  (46.38); policy may use it to gate exposure. */
  model?: string;
  provider?: string;
  /** Request timeout override, clamped by policy. */
  timeoutMs?: number;
  /** Optional user_confirmation prompt hook override for this call. */
  onUserConfirmation?: (request: unknown) => Promise<boolean> | boolean;
}

export type McpInvokeResult =
  | {
      status: "executed";
      ticketId: string;
      capability: string;
      capabilityVersion: number;
      risk: RiskLevel;
      result: McpNormalizedResult;
      sandboxed: boolean;
      /** True when the execution outcome is ambiguous (e.g. timeout while
       *  waiting for the server response after the request was sent). */
      ambiguous?: boolean;
    }
  | {
      status: "approval_required";
      strategy: ApprovalStrategy;
      challengeId: string;
      summary: Record<string, unknown>;
      risk: RiskLevel;
      payload?: string;
    }
  | {
      status: "denied";
      code: string;
      reason: string;
      risk?: RiskLevel;
    }
  | {
      status: "clarification_required";
      questions: {
        field: string;
        reason: string;
        type?: string;
        options?: readonly string[];
      }[];
      reason: string;
    }
  | {
      status: "in_progress";
      reason: string;
    };

/** Metrics snapshot (46.33). */
export interface McpMetrics {
  connectedServers: number;
  authenticatedServers: number;
  revokedServers: number;
  toolCalls: number;
  deniedCalls: number;
  approvalRequests: number;
  approvalLatencyMs: { sum: number; count: number; p95: number };
  ticketFailures: number;
  schemaChanges: number;
  authenticationFailures: number;
  policyDenials: number;
  sandboxFailures: number;
  timeouts: number;
  errors: number;
  resourcesRead: number;
}

export interface McpQualityFlags {
  secretsDetected: boolean;
  truncated: boolean;
  injectionLike: boolean;
  contentTooLarge: boolean;
}
