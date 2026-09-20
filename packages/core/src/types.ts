/**
 * RTQ core security model.
 *
 * Concepts are deliberately separated:
 *
 *   Command   — a structured, validated request { capability, version, input }.
 *   Capability— an explicitly registered executable operation with a schema.
 *   Risk      — the AUTHORITATIVE risk computed by RTQ, never caller-supplied.
 *   Policy    — declarative rules that shape risk, approval and sandboxing.
 *   Clarification — structured questions when security-critical parameters
 *                are missing; no authorization happens in that state.
 *   Approval  — human/device consent for an operation.
 *   Authorization Ticket — a short-lived, single-use, cryptographically
 *                signed entitlement bound to the exact operation.
 *   Execution — consuming an already-verified authorization inside the
 *                required enforcement boundary.
 *   Sandbox   — the OS-level enforcement boundary.
 *   Audit     — structured, redacted security events.
 */

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type Origin =
  "local" | "remote" | "mobile" | "plugin" | "agent" | "automation" | "unknown";

/**
 * MCP-specific authorization-ticket bindings (see section 46.8 of the RTQ
 * spec). A ticket carrying these bindings is cryptographically bound to the
 * exact MCP operation: server identity, tool, canonicalized schema hash,
 * tenant and resource scope. The executor independently validates these
 * bindings at redemption, so a ticket cannot be transplanted across servers,
 * tools, schemas, tenants or resource scopes.
 *
 * All values are ATTRIbution data decided by RTQ — never by the MCP server.
 */
export interface McpTicketBindings {
  /** Stable RTQ server id (never the server's self-declared name). */
  serverId: string;
  /** Exact tool name as executed against the server. */
  toolName: string;
  /** SHA-256 of the canonicalized, RTQ-normalized tool schema. */
  schemaHash: string;
  /** Hash of the verified server identity material (e.g. TLS certificate
   *  fingerprint, endpoint, transport). This is a defensible LABEL when
   *  identity could not be independently verified; policy must treat
   *  unverified identity conservatively. */
  serverIdentity?: string;
  /** Tenant/workspace context the authorization is confined to. */
  tenant?: string;
  /** Resource scope (e.g. repository path) the authorization is confined to. */
  resourceScope?: string;
  /** Credential class (read/write/admin) used by the operation. */
  credentialClass?: string;
}

export type ApprovalStrategy =
  | "automatic"
  | "user_confirmation"
  | "device_verification"
  | "biometric"
  | "qr"
  | "custom";

export type DecisionStatus =
  "allowed" | "denied" | "clarification_required" | "approval_required";

export type SandboxRequirement = "required" | "recommended" | "optional";

export type NetworkPolicy = "none" | { allow: readonly string[] };

/** Caller-facing structured command. `origin` is a HINT only and never
 *  trusted to lower risk (see risk engine). */
export interface Command {
  capability: string;
  version: number;
  input: Record<string, unknown>;
  origin?: Origin;
  metadata?: Record<string, unknown>;
}

/** Risk factors per capability declaration. */
export interface RiskCapabilityFactors {
  base: RiskLevel | "custom";
  /** Additional factors that can only RAISE the base level. */
  reversible?: boolean;
  dataSensitivity?: "none" | "personal" | "secret" | "critical";
  financialImpact?: boolean;
  privilegeImpact?: boolean;
  requiresNetwork?: boolean;
  touchesSystem?: boolean;
}

export interface SandboxSpec {
  filesystem?: {
    read?: readonly string[];
    write?: readonly string[];
    delete?: readonly string[];
    execute?: readonly string[];
  };
  /** 'none' denies all network; a domain allowlist is only honored on
   *  platforms that can enforce it at the OS layer (currently: none). */
  network?: NetworkPolicy;
  processes?: { spawn?: boolean };
  environment?: { allow?: readonly string[]; deny?: readonly string[] };
  requirement?: SandboxRequirement;
}

export interface ApprovalRequirement {
  /** Strategy from `automatic | user_confirmation | device_verification |
   *  biometric | qr | custom`. */
  strategy: ApprovalStrategy;
  /** When true, approval is mandatory even for low risk. */
  always?: boolean;
  /** Highest risk level eligible for automatic approval. */
  maxRiskToAutoApprove?: RiskLevel;
}

/** The registered capability definition — the ONLY executable surface. */
export interface CapabilityDef {
  name: string;
  version: number;
  description: string;
  inputSchema: Schema;
  risk: RiskCapabilityFactors;
  approval?: ApprovalRequirement;
  sandbox?: SandboxSpec;
  /**
   * When present, every ticket issued for this capability additionally binds
   * these MCP operation facts, and the executor verifies them at redemption.
   * serverId/toolName are encoded in the capability name
   * (`mcp://<serverId>/<toolName>`) and re-verified here.
   */
  mcp?: McpTicketBindings;
  execute: (
    context: ExecutionContext,
    input: Record<string, unknown>,
  ) => Promise<ExecutionResult>;
}

export interface ExecutionContext {
  capability: string;
  capabilityVersion: number;
  actor: string;
  origin: Origin;
  ticketId: string;
  risk: RiskLevel;
  /** Tenant/workspace the ticket was authorized for, when bound. */
  tenant?: string;
  /** Full MCP ticket bindings when this capability is MCP-backed. */
  mcp?: McpTicketBindings;
}

export type ExecutionResult =
  { ok: true; data?: unknown } | { ok: false; error: string; code?: string };

export interface RegisteredCapabilitySummary {
  name: string;
  version: number;
  description: string;
  baseRisk: RiskLevel | "custom";
  approvalStrategy: ApprovalStrategy;
  sandboxRequirement: SandboxRequirement;
}

export interface RiskContribution {
  factor: string;
  detail?: string;
}

export interface RiskEvaluation {
  level: RiskLevel;
  baseLevel: RiskLevel;
  contributions: RiskContribution[];
  /** Version of the risk-engine policy that produced this evaluation. */
  policyVersion: string;
}

export type PolicyDecision =
  | { decision: "allow"; reason: string; overrides?: { risk?: RiskLevel } }
  | { decision: "deny"; reason: string; code: string }
  | {
      decision: "clarification_required";
      reason: string;
      questions: ClarificationQuestion[];
    }
  | {
      decision: "approval_required";
      strategy: ApprovalStrategy;
      reason: string;
    };

export interface ClarificationQuestion {
  field: string;
  reason: string;
  type?: "string" | "number" | "path" | "enum" | "confirmation";
  options?: readonly string[];
}

/** Result of the authorize() pipeline. */
export type AuthorizationResult =
  | {
      decision: "allowed";
      ticketId: string;
      capability: string;
      capabilityVersion: number;
      risk: RiskLevel;
      approvalMethod: ApprovalStrategy;
      origin: Origin;
      expiresAt: number;
    }
  | {
      decision: "denied";
      code: string;
      reason: string;
      risk?: RiskLevel;
    }
  | {
      decision: "clarification_required";
      questions: ClarificationQuestion[];
      reason: string;
    }
  | {
      decision: "approval_required";
      strategy: ApprovalStrategy;
      challengeId: string;
      reason: string;
      summary: Record<string, unknown>;
      /** Authoritative risk of the pending operation (RTQ-computed). */
      risk: RiskLevel;
      /** Origin of the pending operation. */
      origin: Origin;
      /** Capability the approval would authorize. */
      capability: string;
      capabilityVersion: number;
    };

/** The pure, inspectable authorization fact consumed by the executor.
 *  It contains no logic — only the facts of the authorization. */
export interface AuthorizationDecision {
  allowed: true;
  ticketId: string;
  capability: string;
  capabilityVersion: number;
  inputHash: string;
  risk: RiskLevel;
  policyVersion: string;
  approvalMethod: ApprovalStrategy;
  origin: Origin;
  actor: string;
  expiresAt: number;
}

/** Schema validator types (see schema.ts). */
export type Schema = { [key: string]: unknown } & object;

export const RISK_LEVELS: readonly RiskLevel[] = [
  "low",
  "medium",
  "high",
  "critical",
];
export const RISK_ORDER: ReadonlyMap<RiskLevel, number> = new Map([
  ["low", 0],
  ["medium", 1],
  ["high", 2],
  ["critical", 3],
]);

export function riskRank(level: RiskLevel): number {
  return RISK_ORDER.get(level) ?? 0;
}

export function maxRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return riskRank(a) >= riskRank(b) ? a : b;
}

export function raiseRisk(level: RiskLevel, steps: number): RiskLevel {
  const rank = riskRank(level);
  const next = Math.min(RISK_LEVELS.length - 1, rank + steps);
  return RISK_LEVELS[next] as RiskLevel;
}
