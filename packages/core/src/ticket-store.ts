import { AuditLogger, Auditor, NoopSink } from "@rtq/audit";
import {
  canonicalStringify,
  deepFreeze,
  inputHash,
  randomHex,
  signCanonical,
  timingSafeEqualHex,
  uuidV4,
} from "@rtq/crypto";
import type {
  ApprovalStrategy,
  McpTicketBindings,
  Origin,
  RiskLevel,
} from "./types";

export interface TicketBindings {
  capability: string;
  capabilityVersion: number;
  input: Record<string, unknown>;
  actor: string;
  resource: string | null;
  risk: RiskLevel;
  policyVersion: string;
  approvalMethod: ApprovalStrategy;
  origin: Origin;
  challengeId: string;
  nonce: string;
  /** Optional MCP operation bindings (server, tool, schema hash, tenant, ...). */
  mcp?: McpTicketBindings;
}

export interface AuthorizationTicket {
  id: string;
  capability: string;
  capabilityVersion: number;
  inputHash: string;
  actor: string;
  resource: string | null;
  risk: RiskLevel;
  policyVersion: string;
  approvalMethod: ApprovalStrategy;
  origin: Origin;
  challengeId: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  status: "issued" | "redeemed" | "expired" | "invalidated" | "tampered";
  signature: string;
  /** MCP operation bindings (only present for MCP-backed capabilities). */
  mcp?: McpTicketBindings;
}

export type RedeemResult =
  | { ok: true; ticket: AuthorizationTicket; input: Record<string, unknown> }
  | {
      ok: false;
      code:
        | "not_found"
        | "replay"
        | "expired"
        | "invalidated"
        | "tampered"
        | "version_changed"
        | "mcp_binding_mismatch";
      reason: string;
    };

export interface TicketStoreOptions {
  /** HMAC-SHA256 signing key — MUST be stored outside the repository (env/secret store). */
  signingKey: string | Buffer;
  /** Ticket lifetime in ms (default 60s). */
  ttlMs?: number;
  /** Optional auditor for TICKET_ISSUED / TICKET_REDEEMED / TICKET_REPLAYED events. */
  auditor?: Auditor;
  /** Maximum number of live tickets before eviction (LRU by issue time). */
  maxTickets?: number;
}

/** Fields that are signed. Status and signature are excluded by design. */
export function ticketBody(
  ticket: Omit<AuthorizationTicket, "status" | "signature">,
): string {
  const body: Record<string, unknown> = {
    id: ticket.id,
    capability: ticket.capability,
    capabilityVersion: ticket.capabilityVersion,
    inputHash: ticket.inputHash,
    actor: ticket.actor,
    resource: ticket.resource,
    risk: ticket.risk,
    policyVersion: ticket.policyVersion,
    approvalMethod: ticket.approvalMethod,
    origin: ticket.origin,
    challengeId: ticket.challengeId,
    nonce: ticket.nonce,
    issuedAt: ticket.issuedAt,
    expiresAt: ticket.expiresAt,
  };
  // MCP bindings are signed when present; absent for native capabilities the
  // signature body is byte-identical to the pre-MCP format.
  if (ticket.mcp !== undefined) {
    body["mcp"] = ticket.mcp;
  }
  return canonicalStringify(body);
}

function sameMcpBindings(
  a: McpTicketBindings | undefined,
  b: McpTicketBindings | undefined,
): boolean {
  if (a === undefined || b === undefined) return a === b;
  return canonicalStringify(a) === canonicalStringify(b);
}

export class TicketStore {
  private readonly tickets = new Map<
    string,
    { ticket: AuthorizationTicket; input: Record<string, unknown> }
  >();
  private readonly signingKey: string | Buffer;
  private readonly ttlMs: number;
  private readonly auditor: Auditor;
  private readonly maxTickets: number;

  constructor(options: TicketStoreOptions) {
    if (!options.signingKey) {
      throw new Error("TicketStore requires a non-empty signingKey");
    }
    this.signingKey = options.signingKey;
    this.ttlMs = options.ttlMs ?? 60_000;
    // Default to a fully-featured auditor writing to a no-op sink. A bare
    // NoopSink is an AuditSink (write only), not an Auditor (emit), and would
    // crash on the first security transition.
    this.auditor = options.auditor ?? new AuditLogger(new NoopSink());
    this.maxTickets = options.maxTickets ?? 1000;
  }

  /** Issue a signed, single-use authorization ticket bound to the exact operation. */
  issue(bindings: TicketBindings): AuthorizationTicket {
    const now = Date.now();
    const ticket: Omit<AuthorizationTicket, "status" | "signature"> = {
      id: uuidV4(),
      capability: bindings.capability,
      capabilityVersion: bindings.capabilityVersion,
      inputHash: inputHash(bindings.input),
      actor: bindings.actor,
      resource: bindings.resource,
      risk: bindings.risk,
      policyVersion: bindings.policyVersion,
      approvalMethod: bindings.approvalMethod,
      origin: bindings.origin,
      challengeId: bindings.challengeId,
      nonce: bindings.nonce,
      issuedAt: now,
      expiresAt: now + this.ttlMs,
    };
    const signature = signCanonical(this.signingKey, ticketBody(ticket));
    const full: AuthorizationTicket = {
      ...ticket,
      status: "issued",
      signature,
    };
    this.tickets.set(full.id, {
      ticket: full,
      input: deepFreeze(bindings.input) as Record<string, unknown>,
    });
    this.evictIfNeeded();
    return full;
  }

  /**
   * Atomically redeem a ticket. Single-use: the status transition from
   * `issued` to `redeemed` happens synchronously, so two racing redeemers
   * cannot both succeed. Replays, expiry, invalidation and tampering are all
   * rejected with explicit codes. When `expectedMcp` is supplied (MCP-backed
   * capabilities), the ticket's signed MCP bindings must match exactly.
   */
  redeem(
    ticketId: string,
    context: {
      expectedCapability: string;
      expectedVersion: number;
      expectedMcp?: McpTicketBindings;
    },
  ): RedeemResult {
    const entry = this.tickets.get(ticketId);
    if (!entry) {
      return { ok: false, code: "not_found", reason: "Ticket not found" };
    }
    const { ticket } = entry;

    if (ticket.status === "redeemed") {
      this.auditor.emit(
        "TICKET_REPLAYED",
        `Ticket ${ticketId} replayed: already redeemed`,
        { capability: ticket.capability },
        { capability: ticket.capability, ticketId },
      );
      return {
        ok: false,
        code: "replay",
        reason: "Ticket was already redeemed (replay attempt)",
      };
    }
    if (ticket.status === "tampered") {
      return {
        ok: false,
        code: "tampered",
        reason: "Ticket failed signature verification previously",
      };
    }
    if (ticket.status === "invalidated") {
      return {
        ok: false,
        code: "invalidated",
        reason: "Ticket was invalidated",
      };
    }
    if (Date.now() > ticket.expiresAt) {
      this.tickets.delete(ticketId);
      return { ok: false, code: "expired", reason: "Ticket expired" };
    }
    if (ticket.capability !== context.expectedCapability) {
      return {
        ok: false,
        code: "version_changed",
        reason: "Capability mismatch at redemption",
      };
    }
    if (ticket.capabilityVersion !== context.expectedVersion) {
      this.auditor.emit(
        "TICKET_REJECTED",
        `Ticket ${ticketId} rejected: capability version changed (ticket v${ticket.capabilityVersion} != current v${context.expectedVersion})`,
        {
          capability: ticket.capability,
          ticketVersion: ticket.capabilityVersion,
          currentVersion: context.expectedVersion,
        },
        { capability: ticket.capability, ticketId },
      );
      return {
        ok: false,
        code: "version_changed",
        reason: "Capability version changed since ticket issued",
      };
    }
    // MCP binding verification: the ticket is bound to the exact server/tool/
    // schema/tenant it was authorized for. A ticket from server A can never be
    // redeemed while executing server B's tool.
    if (
      context.expectedMcp !== undefined &&
      !sameMcpBindings(ticket.mcp, context.expectedMcp)
    ) {
      this.auditor.emit(
        "TICKET_REJECTED",
        `Ticket ${ticketId} rejected: MCP binding mismatch`,
        { capability: ticket.capability, expectedMcp: context.expectedMcp },
        { capability: ticket.capability, ticketId },
      );
      return {
        ok: false,
        code: "mcp_binding_mismatch",
        reason: "Ticket MCP bindings do not match the executing MCP operation",
      };
    }

    // Tamper check: recompute the signature over the stored body. The stored
    // fields are frozen, so any mutation breaks this check.
    const expected = signCanonical(this.signingKey, ticketBody(ticket));
    if (!timingSafeEqualHex(ticket.signature, expected)) {
      ticket.status = "tampered";
      this.auditor.emit(
        "TICKET_REJECTED",
        `Ticket ${ticketId} failed signature verification`,
        {},
        { capability: ticket.capability, ticketId },
      );
      return {
        ok: false,
        code: "tampered",
        reason: "Ticket signature verification failed",
      };
    }

    // Atomic single-use transition. No awaits above or below this point.
    ticket.status = "redeemed";
    this.auditor.emit(
      "TICKET_REDEEMED",
      `Ticket ${ticketId} redeemed for execution`,
      {
        capability: ticket.capability,
        capabilityVersion: ticket.capabilityVersion,
        risk: ticket.risk,
        origin: ticket.origin,
        approvalMethod: ticket.approvalMethod,
      },
      { capability: ticket.capability, ticketId },
    );
    return { ok: true, ticket: { ...ticket }, input: entry.input };
  }

  /** Invalidates every live ticket for a capability+version (used on replace). */
  invalidateForCapabilityVersion(
    capability: string,
    version: number,
    reason: string,
  ): number {
    let count = 0;
    for (const [, entry] of this.tickets) {
      const t = entry.ticket;
      if (
        t.capability === capability &&
        t.capabilityVersion === version &&
        t.status === "issued"
      ) {
        t.status = "invalidated";
        this.auditor.emit(
          "TICKET_REJECTED",
          `Ticket ${t.id} invalidated: ${reason}`,
          { capability, version, reason },
          { capability, ticketId: t.id },
        );
        count++;
      }
    }
    return count;
  }

  invalidate(ticketId: string, reason: string): boolean {
    const entry = this.tickets.get(ticketId);
    if (!entry) return false;
    if (entry.ticket.status === "issued") {
      entry.ticket.status = "invalidated";
      this.auditor.emit(
        "TICKET_REJECTED",
        `Ticket ${ticketId} invalidated: ${reason}`,
        { reason },
        { capability: entry.ticket.capability, ticketId },
      );
      return true;
    }
    return false;
  }

  /**
   * Invalidate every live (issued) ticket matching a predicate. Used to
   * invalidate all MCP tickets for a server when its identity/endpoint/trust
   * changes. Returns the number of tickets invalidated.
   */
  invalidateWhere(
    predicate: (ticket: AuthorizationTicket) => boolean,
    reason: string,
  ): number {
    let count = 0;
    for (const [, entry] of this.tickets) {
      const t = entry.ticket;
      if (t.status === "issued" && predicate(t)) {
        t.status = "invalidated";
        this.auditor.emit(
          "TICKET_REJECTED",
          `Ticket ${t.id} invalidated: ${reason}`,
          { reason, capability: t.capability },
          { capability: t.capability, ticketId: t.id },
        );
        count++;
      }
    }
    return count;
  }

  peek(
    ticketId: string,
  ): Pick<
    AuthorizationTicket,
    "status" | "capability" | "capabilityVersion" | "risk" | "expiresAt"
  > | null {
    const entry = this.tickets.get(ticketId);
    if (!entry) return null;
    const t = entry.ticket;
    return {
      status: t.status,
      capability: t.capability,
      capabilityVersion: t.capabilityVersion,
      risk: t.risk,
      expiresAt: t.expiresAt,
    };
  }

  get size(): number {
    return this.tickets.size;
  }

  private evictIfNeeded(): void {
    if (this.tickets.size <= this.maxTickets) return;
    const entries = Array.from(this.tickets.entries()).sort(
      (a, b) => a[1].ticket.issuedAt - b[1].ticket.issuedAt,
    );
    const excess = this.tickets.size - this.maxTickets;
    for (let i = 0; i < excess; i++) {
      this.tickets.delete(entries[i]![0]);
    }
  }

  /** Deterministic ticket signature for cross-process verification. */
  verifySignature(ticket: AuthorizationTicket): boolean {
    const expected = signCanonical(this.signingKey, ticketBody(ticket));
    return timingSafeEqualHex(ticket.signature, expected);
  }
}

export { randomHex };
