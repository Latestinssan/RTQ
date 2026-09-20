/**
 * RTQ MCP credential vault (spec §46.24–46.25).
 *
 * SCOPE: Stores and retrieves credentials scoped by agent, server, tool,
 * and tenant. Credentials are NEVER returned to servers; the vault only
 * hands them to the transport layer via a scoped injection callback.
 *
 * CREDENTIAL LIFECYCLE:
 *   1. Operator/agent stores a credential via `store()`.
 *   2. Gateway calls `retrieve()` before each tool invocation to inject
 *      credentials into the transport layer.
 *   3. `revoke()` immediately removes the credential and invalidates any
 *      in-flight requests that used it (via the optional `onRevoke` callback).
 *
 * FAIL-CLOSED: `retrieve()` returns `undefined` when no credential matches.
 * The gateway must deny the invocation (46.28 #8).
 */
import type { McpCredentialClass } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A stored credential record. */
export interface McpCredentialRecord {
  /** Unique ID for this credential (generated on store). */
  id: string;
  /** Credential class (api_key, oauth_token, etc.). */
  credentialClass: McpCredentialClass;
  /** The credential payload (opaque string; the vault never inspects it). */
  credential: string;
  /** Agent that owns this credential (optional; null = global). */
  agentId?: string;
  /** Server this credential is scoped to. */
  serverId: string;
  /** Tool this credential is scoped to (optional; null = server-wide). */
  toolName?: string;
  /** Tenant this credential belongs to (optional; null = cross-tenant). */
  tenant?: string;
  /** Timestamp (ms) when the credential was stored. */
  createdAt: number;
  /** Timestamp (ms) when the credential was last used. Null = never. */
  lastUsedAt: number | null;
  /** Optional expiry timestamp (ms). Null = no expiry. */
  expiresAt: number | null;
  /** Number of times this credential has been used. */
  useCount: number;
  /** Operator-supplied metadata (audited, never sent to server). */
  metadata?: Record<string, unknown>;
}

/** Scoping parameters for credential lookup. */
export interface McpCredentialLookupScope {
  agentId?: string;
  serverId: string;
  toolName?: string;
  tenant?: string;
}

/** Options for `store()`. */
export interface McpCredentialStoreOptions {
  credential: string;
  credentialClass: McpCredentialClass;
  agentId?: string;
  serverId: string;
  toolName?: string;
  tenant?: string;
  expiresAt?: number | null;
  metadata?: Record<string, unknown>;
}

/** Callback invoked when a credential is revoked. */
export type McpCredentialRevokeCallback = (record: McpCredentialRecord) => void;

/** Callback invoked when a credential is used. */
export type McpCredentialUseCallback = (record: McpCredentialRecord) => void;

// ---------------------------------------------------------------------------
// McpCredentialVault (interface)
// ---------------------------------------------------------------------------

/**
 * Credential vault for MCP tool invocations. The gateway owns one vault
 * instance and injects it into every gateway construction.
 */
export interface McpCredentialVault {
  /**
   * Store a credential. Returns the generated record with a unique `id`.
   * If a credential already exists for the same scope + class, it is
   * overwritten (old record revoked).
   */
  store(options: McpCredentialStoreOptions): McpCredentialRecord;

  /**
   * Retrieve the best-matching credential for a scope. Returns `undefined`
   * when no credential matches (fail-closed).
   *
   * Match priority (most specific wins):
   *   1. agentId + serverId + toolName + tenant
   *   2. agentId + serverId + toolName
   *   3. agentId + serverId + tenant
   *   4. agentId + serverId
   *   5. serverId + toolName + tenant
   *   6. serverId + toolName
   *   7. serverId + tenant
   *   8. serverId
   *
   * Expired credentials are skipped. Non-expired credentials are returned
   * in order of specificity; `lastUsedAt` is updated on retrieval.
   */
  retrieve(scope: McpCredentialLookupScope): McpCredentialRecord | undefined;

  /**
   * Revoke a credential by ID. Returns the revoked record, or `undefined`
   * if no credential with that ID exists.
   */
  revoke(id: string): McpCredentialRecord | undefined;

  /**
   * Revoke ALL credentials matching a scope. Returns the number of
   * credentials revoked. Triggers `onRevoke` for each.
   */
  revokeScope(scope: McpCredentialLookupScope): number;

  /**
   * Revoke ALL credentials for a server. Returns the number revoked.
   * Used when a server is disconnected or its trust is withdrawn (46.30).
   */
  revokeServer(serverId: string): number;

  /** List all credentials (optionally scoped). Admin use only. */
  list(scope?: Partial<McpCredentialLookupScope>): McpCredentialRecord[];

  /** Count of non-expired credentials. */
  count(): number;

  /** Remove expired credentials. Returns the number purged. */
  purgeExpired(): number;

  /** Register a callback for credential revocation events. */
  onRevoke(callback: McpCredentialRevokeCallback): void;

  /** Register a callback for credential use events. */
  onUse(callback: McpCredentialUseCallback): void;
}

// ---------------------------------------------------------------------------
// InMemoryCredentialVault
// ---------------------------------------------------------------------------

let _vaultId = 0;

/**
 * In-memory credential vault. Credentials do not survive process restarts.
 * For production use, back this with persistent storage via the vault
 * interface.
 */
export class InMemoryCredentialVault implements McpCredentialVault {
  private readonly records = new Map<string, McpCredentialRecord>();
  private readonly revokeCallbacks: McpCredentialRevokeCallback[] = [];
  private readonly useCallbacks: McpCredentialUseCallback[] = [];

  private nextId(): string {
    return `mcp_cred_${++_vaultId}_${Date.now().toString(36)}`;
  }

  store(options: McpCredentialStoreOptions): McpCredentialRecord {
    // Check for existing credential in the same scope + class; revoke it first
    const existing = this.findExact({
      serverId: options.serverId,
      toolName: options.toolName,
      agentId: options.agentId,
      tenant: options.tenant,
    }, options.credentialClass);
    if (existing) {
      this.revoke(existing.id);
    }

    const record: McpCredentialRecord = {
      id: this.nextId(),
      credentialClass: options.credentialClass,
      credential: options.credential,
      agentId: options.agentId,
      serverId: options.serverId,
      toolName: options.toolName,
      tenant: options.tenant,
      createdAt: Date.now(),
      lastUsedAt: null,
      expiresAt: options.expiresAt ?? null,
      useCount: 0,
      metadata: options.metadata,
    };

    this.records.set(record.id, record);
    return { ...record };
  }

  retrieve(scope: McpCredentialLookupScope): McpCredentialRecord | undefined {
    const now = Date.now();
    const candidates = this.findCandidates(scope)
      .filter((r) => r.expiresAt === null || r.expiresAt > now)
      .sort((a, b) => this.specificity(a, scope) - this.specificity(b, scope));

    // Most specific last (reversed) → pick last for highest specificity
    const best = candidates[candidates.length - 1];
    if (!best) return undefined;

    // Update usage stats
    best.lastUsedAt = now;
    best.useCount++;

    // Fire use callbacks (fire-and-forget)
    for (const cb of this.useCallbacks) {
      try { cb({ ...best }); } catch { /* callback errors are swallowed */ }
    }

    return { ...best };
  }

  revoke(id: string): McpCredentialRecord | undefined {
    const record = this.records.get(id);
    if (!record) return undefined;
    this.records.delete(id);

    for (const cb of this.revokeCallbacks) {
      try { cb({ ...record }); } catch { /* swallowed */ }
    }

    return { ...record };
  }

  revokeScope(scope: McpCredentialLookupScope): number {
    const matches = this.findCandidates(scope);
    for (const r of matches) {
      this.revoke(r.id);
    }
    return matches.length;
  }

  revokeServer(serverId: string): number {
    const matches = this.findCandidates({ serverId });
    for (const r of matches) {
      this.revoke(r.id);
    }
    return matches.length;
  }

  list(scope?: Partial<McpCredentialLookupScope>): McpCredentialRecord[] {
    if (!scope || Object.keys(scope).length === 0) {
      return [...this.records.values()].map((r) => ({ ...r }));
    }
    return this.findCandidates(scope as McpCredentialLookupScope).map((r) => ({ ...r }));
  }

  count(): number {
    const now = Date.now();
    let n = 0;
    for (const r of this.records.values()) {
      if (r.expiresAt === null || r.expiresAt > now) n++;
    }
    return n;
  }

  purgeExpired(): number {
    const now = Date.now();
    const expired: string[] = [];
    for (const [id, r] of this.records) {
      if (r.expiresAt !== null && r.expiresAt <= now) {
        expired.push(id);
      }
    }
    for (const id of expired) {
      this.revoke(id);
    }
    return expired.length;
  }

  onRevoke(callback: McpCredentialRevokeCallback): void {
    this.revokeCallbacks.push(callback);
  }

  onUse(callback: McpCredentialUseCallback): void {
    this.useCallbacks.push(callback);
  }

  // -- Private helpers --

  private findCandidates(scope: McpCredentialLookupScope): McpCredentialRecord[] {
    const result: McpCredentialRecord[] = [];
    for (const r of this.records.values()) {
      if (r.serverId !== scope.serverId) continue;
      if (scope.agentId !== undefined && r.agentId !== undefined && r.agentId !== scope.agentId) continue;
      if (scope.toolName !== undefined && r.toolName !== undefined && r.toolName !== scope.toolName) continue;
      if (scope.tenant !== undefined && r.tenant !== undefined && r.tenant !== scope.tenant) continue;
      result.push(r);
    }
    return result;
  }

  private findExact(
    scope: McpCredentialLookupScope,
    credentialClass: McpCredentialClass,
  ): McpCredentialRecord | undefined {
    for (const r of this.records.values()) {
      if (r.credentialClass !== credentialClass) continue;
      if (r.serverId !== scope.serverId) continue;
      if ((scope.agentId ?? null) !== (r.agentId ?? null)) continue;
      if ((scope.toolName ?? null) !== (r.toolName ?? null)) continue;
      if ((scope.tenant ?? null) !== (r.tenant ?? null)) continue;
      return r;
    }
    return undefined;
  }

  /**
   * Specificity score: lower = more specific. Weights the presence of each
   * scope field. Non-matching scope values get a high penalty so they sort
   * last (but are already filtered out by `findCandidates`).
   */
  private specificity(record: McpCredentialRecord, scope: McpCredentialLookupScope): number {
    let score = 0;
    if (record.agentId !== undefined) score += 1;
    if (record.toolName !== undefined) score += 2;
    if (record.tenant !== undefined) score += 4;
    // Prefer exact scope matches
    if (scope.agentId !== undefined && record.agentId === scope.agentId) score -= 8;
    if (scope.toolName !== undefined && record.toolName === scope.toolName) score -= 8;
    if (scope.tenant !== undefined && record.tenant === scope.tenant) score -= 8;
    return score;
  }
}
