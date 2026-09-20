/**
 * RTQ structured security event taxonomy.
 *
 * Every meaningful security transition emits one of these events. The event
 * name is the first-class audit primitive — consumers must never have to grep
 * prose to reconstruct what happened.
 */

export const AUDIT_EVENTS = [
  "CAPABILITY_REGISTERED",
  "COMMAND_RECEIVED",
  "AUTHORIZATION_REQUESTED",
  "CLARIFICATION_REQUIRED",
  "RISK_EVALUATED",
  "APPROVAL_REQUESTED",
  "APPROVAL_GRANTED",
  "APPROVAL_DENIED",
  "VERIFICATION_STARTED",
  "VERIFICATION_FAILED",
  "TICKET_ISSUED",
  "TICKET_REDEEMED",
  "TICKET_REJECTED",
  "TICKET_REPLAYED",
  "SANDBOX_CREATED",
  "SANDBOX_FAILED",
  "EXECUTION_STARTED",
  "EXECUTION_COMPLETED",
  "EXECUTION_DENIED",
  "POLICY_EVALUATED",
  "POLICY_CONFIGURED",
  // MCP integration events (RTQ spec section 46.22). Event names are the
  // first-class audit primitive; the MCP event set mirrors the core taxonomy
  // so a single audit stream reconstructs MCP security decisions.
  "MCP_SERVER_REGISTERED",
  "MCP_SERVER_CONNECTED",
  "MCP_SERVER_AUTHENTICATED",
  "MCP_SERVER_APPROVED",
  "MCP_SERVER_RESTRICTED",
  "MCP_SERVER_REVOKED",
  "MCP_SERVER_BLOCKED",
  "MCP_CONNECTION_FAILED",
  "MCP_TOOL_DISCOVERED",
  "MCP_TOOL_REGISTERED",
  "MCP_TOOL_SCHEMA_CHANGED",
  "MCP_TOOL_REQUESTED",
  "MCP_TOOL_CLARIFICATION_REQUIRED",
  "MCP_TOOL_APPROVAL_REQUESTED",
  "MCP_TOOL_APPROVED",
  "MCP_TOOL_DENIED",
  "MCP_TOOL_TICKET_REJECTED",
  "MCP_TOOL_EXECUTED",
  "MCP_TOOL_FAILED",
  "MCP_RESOURCE_ACCESSED",
  "MCP_RESOURCE_DENIED",
  "MCP_PROMPT_DELIVERED",
  "MCP_CREDENTIAL_DENIED",
  "MCP_SUBCAPABILITY_DENIED",
  "MCP_LIMIT_ENFORCED",
] as const;

export type AuditEventName = (typeof AUDIT_EVENTS)[number];

export interface AuditEvent {
  /** Monotonic sequence number within this audit stream. */
  seq: number;
  event: AuditEventName;
  /** Unix epoch milliseconds. */
  timestamp: number;
  /** Human+machine readable summary of WHAT happened and WHY. */
  message: string;
  /**
   * Structured context. MUST be a JSON-serializable object. Values that look
   * like secrets are redacted when emitted by the RTQ auditor; callers should
   * still avoid placing raw secrets here.
   */
  context: Record<string, unknown>;
  /** Capability name involved, when applicable. */
  capability?: string;
  /** Ticket id involved, when applicable. */
  ticketId?: string;
}

/** Redaction policy applied to every emitted event. */
export interface AuditRedactionPolicy {
  /** Extra secret values (e.g. a configured HMAC key) to scrub from context. */
  secretValues?: ReadonlySet<string>;
}

export interface AuditSink {
  write(event: AuditEvent): void;
}

export interface Auditor {
  emit(
    event: AuditEventName,
    message: string,
    context?: Record<string, unknown>,
    refs?: { capability?: string; ticketId?: string },
  ): void;
  readonly sink: AuditSink;
  /** In-memory events emitted so far (for tests and diagnostics). */
  readonly events: readonly AuditEvent[];
  /** Snapshot of all events (copy). */
  snapshot(): AuditEvent[];
}
