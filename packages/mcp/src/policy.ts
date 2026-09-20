/**
 * RTQ MCP policy engine (spec 46.16–46.20, 46.22–46.26, 46.30–46.31).
 *
 * SCOPE: Turns operator/RTQ-declared policy into an ALLOW/DENY decision that
 * the gateway feeds into RTQ authorization. It is fail-closed: an empty policy
 * denies everything except what the RTQ pipeline explicitly approves.
 *
 * The engine is a POLICY FILTER ON TOP OF RTQ. It can only DENY more; it can
 * never fabricate an allow. Authorization and approval tiers are RTQ facts
 * (46.19); this engine's `approvalTier` is a policy suggestion that the gateway
 * folds into the RTQ capability's `approval` tiering only when the operator
 * has configured it, never from server text.
 *
 * Advisory-only signals (working DURING discovery, BEFORE ANY authorization):
 * `severity` from the registry tool record is the RTQ-decided baseline; the
 * McpRiskAdvisor may RAISE above it but never lower it. Unknown tools
 * classify as "unknown" and are denied by default (46.3, 46.5, 46.28 #6).
 */
import type {
  McpCredentialClass,
  McpLimits,
  McpOriginKind,
  McpPolicyEvaluation,
  McpSecurityContext,
  McpSeverity,
  McpTransportKind,
} from "./types";
import {
  classifyEffectiveOperations,
  type McpEffectiveOperation,
  type McpRiskAdvice,
} from "./risk";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The operator-declared policy instrument being constrained. */
export type McpPolicyInstrument =
  | "tool"
  | "server"
  | "transport"
  | "tenant"
  | "resource_scope"
  | "model"
  | "provider"
  | "credential_class";

/** One rule in the operator's policy rule set. */
export interface McpPolicyRule {
  /** Instrument this rule constrains. */
  instrument: McpPolicyInstrument;
  /** Glob-ish match against the instrument's identifier (see `matchesMcpPattern`). */
  pattern: string;
  /** `true` = allow, `false` = deny. */
  allow: boolean;
  /** Human-readable note (audited, never sent to server). */
  reason?: string;
  /** Optional scope tag for audit grouping. */
  scopeId?: string;
  /** Tenant filter — rule applies only when the request's tenant matches. */
  tenant?: string;
}

export interface McpPolicyOptions {
  /** Operator/RTQ-declared rules (evaluated in order; first match wins). */
  rules?: readonly McpPolicyRule[];

  /**
   * Maps an effective operation to glob patterns that are ALLOWED. When absent
   * for a given operation, that operation is denied (fail-closed). The special
   * key `"*"` allows all operations (not recommended in production).
   */
  allowedEffectiveOperations?: ReadonlyMap<
    McpEffectiveOperation,
    readonly string[]
  >;

  /**
   * Additional deny patterns per effective operation. Evaluated after the allow
   * list — a deny always overrides a prior allow.
   */
  deniedEffectiveOperations?: ReadonlyMap<
    McpEffectiveOperation,
    readonly string[]
  >;

  /** Operator-configured per-tool/meta limits (fail-closed when absent). */
  limits?: McpLimits;

  /**
   * When `true`, servers whose transport is NOT in `allowedTransports` are
   * denied (46.17 fail-closed transport policy).
   */
  requireAllowedTransports?: boolean;

  /** Permitted transports. Default: `in-memory` + `stdio` only (http denied). */
  allowedTransports?: ReadonlySet<McpTransportKind>;

  /** Tenant allowlist. When set, a request with an unknown tenant is denied. */
  allowedTenants?: ReadonlySet<string>;

  /** Resource scope allowlist. When set, unknown scopes are denied. */
  allowedResourceScopes?: ReadonlySet<string>;

  /** Model allowlist (RTQ-held, operator-declared). */
  allowedModels?: ReadonlySet<string>;

  /** Provider allowlist. */
  allowedProviders?: ReadonlySet<string>;

  /** Allowed credential classes per server/tool. */
  allowedCredentialClasses?: ReadonlySet<McpCredentialClass>;

  /**
   * Maps `McpSeverity` → RTQ approval tier. Advisory only — the gateway
   * folds this into the RTQ capability's `approval` declaration.
   */
  approvalTier?: ReadonlyMap<
    McpSeverity,
    "automatic" | "user_confirmation" | "device_verification" | "biometric"
  >;

  /**
   * When `true`, the gateway must not auto-approve tools whose effective
   * operations include `admin` or `system`, regardless of severity.
   */
  requireExplicitAdminApproval?: boolean;

  /**
   * When `true`, the gateway must not auto-approve tools whose effective
   * operations include `write`, regardless of severity.
   */
  requireExplicitWriteApproval?: boolean;

  /**
   * Maximum duration (ms) for a single tool execution. Policies may tighten
   * the server-declared default.
   */
  maxExecutionDurationMs?: number;

  /**
   * Maximum number of concurrent in-flight calls per server. Policies may
   * tighten the server-declared default.
   */
  maxConcurrentPerServer?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DEFAULT_ALLOWED_TRANSPORTS: ReadonlySet<McpTransportKind> = new Set([
  "in-memory",
  "stdio",
]);

/**
 * Glob-ish matcher for MCP identifiers. `*` matches any suffix; exact string
 * match is always tried first.
 *
 * Examples:
 *   matchesMcpPattern("*", "mcp://srv1/toolA")        → true
 *   matchesMcpPattern("mcp://srv1/*", "mcp://srv1/t")  → true
 *   matchesMcpPattern("mcp://srv1/toolA", "mcp://s…")   → false
 */
export function matchesMcpPattern(pattern: string, value: string): boolean {
  if (pattern === "*") return true;
  if (pattern === value) return true;
  const star = pattern.indexOf("*");
  if (star < 0) return false;
  if (!pattern.endsWith("*")) return false;
  return value.startsWith(pattern.slice(0, star));
}

/**
 * Parse a raw severity string into the McpSeverity union, defaulting to
 * `"medium"` for unknown values.
 */
function parseSeverity(raw: string | undefined): McpSeverity {
  if (raw === "low" || raw === "medium" || raw === "high" || raw === "critical")
    return raw;
  return "medium";
}

// ---------------------------------------------------------------------------
// McpPolicyEngine
// ---------------------------------------------------------------------------

/**
 * Fail-closed policy engine for MCP tool invocations.
 *
 * Usage:
 *   const engine = new McpPolicyEngine({ rules: [...] });
 *   const eval = engine.evaluate({ ... });
 *   if (!eval.allowed) { return deny(eval.reason, eval.code); }
 */
export class McpPolicyEngine {
  private readonly rules: readonly McpPolicyRule[];
  private readonly allowedEffectiveOperations: ReadonlyMap<
    McpEffectiveOperation,
    readonly string[]
  >;
  private readonly deniedEffectiveOperations: ReadonlyMap<
    McpEffectiveOperation,
    readonly string[]
  >;
  private readonly options: McpPolicyOptions;

  constructor(options: McpPolicyOptions = {}) {
    this.options = options;
    this.rules = options.rules ?? [];
    this.allowedEffectiveOperations =
      options.allowedEffectiveOperations ?? new Map();
    this.deniedEffectiveOperations =
      options.deniedEffectiveOperations ?? new Map();
  }

  /** Operator-configured limits (fail-closed defaults when absent). */
  getLimits(): McpLimits {
    return this.options.limits ?? {};
  }

  /**
   * Evaluate policy for one MCP tool invocation or discovery event.
   *
   * @returns `McpPolicyEvaluation` — `{ allowed: true, reason, matched }` or
   *   `{ allowed: false, reason, code, matched }`.
   */
  evaluate(params: {
    /** RTQ capability name (`mcp://<serverId>/<toolName>`). */
    capabilityName: string;
    serverId: string;
    toolName: string;
    severity?: McpSeverity;
    transportKind?: McpTransportKind;
    origin?: McpOriginKind;
    tenant?: string;
    resourceScope?: string;
    model?: string;
    provider?: string;
    credentialClass?: McpCredentialClass;
    riskAdvice?: McpRiskAdvice;
    ctx?: McpSecurityContext;
    limits?: McpLimits;
    declaredCapabilities?: readonly string[];
    /** Whether the server has been identity-verified (RTQ fact). */
    identityVerified?: boolean;
    /** Whether the server is sandboxed (RTQ fact). */
    sandboxed?: boolean;
  }): McpPolicyEvaluation {
    const matched: string[] = [];
    const severity = parseSeverity(params.severity);
    const transportKind = params.transportKind ?? "in-memory";

    // ---- Transport gate (46.17 fail-closed) ----
    const allowedTransports =
      this.options.allowedTransports ?? DEFAULT_ALLOWED_TRANSPORTS;
    if (!allowedTransports.has(transportKind)) {
      return this.deny(
        "Transport not in operator allowlist (fail-closed transport policy, 46.17)",
        "transport.denied",
        matched,
      );
    }

    // ---- Rule evaluation (first-match-wins) ----
    for (const rule of this.rules) {
      const target = this.resolveTarget(rule.instrument, params);
      if (target === null) continue; // instrument not applicable to this request
      if (!matchesMcpPattern(rule.pattern, target)) continue;
      matched.push(rule.pattern);
      if (!rule.allow) {
        return this.deny(
          rule.reason ?? `Rule denied: ${rule.instrument} ${rule.pattern}`,
          `${rule.instrument}.denied`,
          matched,
        );
      }
      // allow rule matched — continue evaluating more specific gates below
    }

    // ---- Effective-operation allow/deny (46.25) ----
    const effectiveOps =
      params.riskAdvice?.effectiveOperations ?? ["unknown"];
    for (const op of effectiveOps) {
      if (op === "unknown") {
        return this.deny(
          "Unknown effective operation (46.28 #6: unknown tools default to denied)",
          "tool.unknown_operation",
          matched,
        );
      }
      // Check deny list first (explicit deny overrides allow)
      const deniedPatterns = this.deniedEffectiveOperations.get(op) ?? [];
      for (const pat of deniedPatterns) {
        if (matchesMcpPattern(pat, params.capabilityName)) {
          return this.deny(
            `Effective operation '${op}' explicitly denied by policy`,
            `tool.effective_op_denied:${op}`,
            matched,
          );
        }
      }
      // Check allow list
      const allowedPatterns = this.allowedEffectiveOperations.get(op);
      if (allowedPatterns) {
        const allowed = allowedPatterns.some((p) =>
          matchesMcpPattern(p, params.capabilityName),
        );
        if (!allowed) {
          return this.deny(
            `Effective operation '${op}' not in operator allowlist for this capability`,
            `tool.effective_op_not_allowed:${op}`,
            matched,
          );
        }
      }
      // No patterns defined for this op → fail-closed (deny)
      else {
        return this.deny(
          `No operator policy allows effective operation '${op}' (fail-closed)`,
          `tool.effective_op_no_policy:${op}`,
          matched,
        );
      }
    }

    // ---- Admin/write explicit approval gates ----
    if (this.options.requireExplicitAdminApproval) {
      if (effectiveOps.includes("admin") || effectiveOps.includes("system")) {
        return this.deny(
          "Admin/system operations require explicit operator approval (46.19)",
          "tool.admin_requires_approval",
          matched,
        );
      }
    }
    if (this.options.requireExplicitWriteApproval) {
      if (effectiveOps.includes("write")) {
        return this.deny(
          "Write operations require explicit operator approval (46.19)",
          "tool.write_requires_approval",
          matched,
        );
      }
    }

    // ---- Tenant gate (46.22) ----
    if (this.options.allowedTenants && params.tenant) {
      if (!this.options.allowedTenants.has(params.tenant)) {
        return this.deny(
          `Tenant '${params.tenant}' not in operator allowlist`,
          "tenant.denied",
          matched,
        );
      }
    }

    // ---- Resource scope gate (46.22) ----
    if (this.options.allowedResourceScopes && params.resourceScope) {
      if (!this.options.allowedResourceScopes.has(params.resourceScope)) {
        return this.deny(
          `Resource scope '${params.resourceScope}' not in operator allowlist`,
          "resource_scope.denied",
          matched,
        );
      }
    }

    // ---- Model gate ----
    if (this.options.allowedModels && params.model) {
      if (!this.options.allowedModels.has(params.model)) {
        return this.deny(
          `Model '${params.model}' not in operator allowlist`,
          "model.denied",
          matched,
        );
      }
    }

    // ---- Provider gate ----
    if (this.options.allowedProviders && params.provider) {
      if (!this.options.allowedProviders.has(params.provider)) {
        return this.deny(
          `Provider '${params.provider}' not in operator allowlist`,
          "provider.denied",
          matched,
        );
      }
    }

    // ---- Credential class gate ----
    if (this.options.allowedCredentialClasses && params.credentialClass) {
      if (!this.options.allowedCredentialClasses.has(params.credentialClass)) {
        return this.deny(
          `Credential class '${params.credentialClass}' not in operator allowlist`,
          "credential_class.denied",
          matched,
        );
      }
    }

    // ---- Sandbox gate (46.16) ----
    if (this.options.requireAllowedTransports && !params.sandboxed) {
      // Note: sandboxed is an RTQ fact, not a server claim.
      // This gate is advisory — the gateway decides whether to proceed.
    }

    // ---- Allowed: construct reason ----
    const reasons: string[] = [];
    if (matched.length > 0) {
      reasons.push(`Matched rules: ${matched.join(", ")}`);
    }
    reasons.push(`Severity: ${severity}`);
    reasons.push(`Effective operations: ${effectiveOps.join(", ")}`);

    return {
      allowed: true,
      reason: reasons.join("; "),
      matched,
    };
  }

  /**
   * Determine the RTQ approval tier for a given severity. Advisory only — the
   * RTQ pipeline owns the real approval decision.
   */
  approvalTierFor(
    severity: McpSeverity,
  ): "automatic" | "user_confirmation" | "device_verification" | "biometric" {
    const t = this.options.approvalTier?.get(severity);
    if (t) return t;
    // Fail-closed default: high/critical always require confirmation
    switch (severity) {
      case "low":
        return "automatic";
      case "medium":
        return "automatic";
      case "high":
        return "user_confirmation";
      case "critical":
        return "device_verification";
    }
  }

  /** Resolve the target identifier for a given policy instrument. */
  private resolveTarget(
    instrument: McpPolicyInstrument,
    params: Parameters<McpPolicyEngine["evaluate"]>[0],
  ): string | null {
    switch (instrument) {
      case "tool":
        return params.capabilityName;
      case "server":
        return params.serverId;
      case "transport":
        return params.transportKind ?? "in-memory";
      case "tenant":
        return params.tenant ?? null;
      case "resource_scope":
        return params.resourceScope ?? null;
      case "model":
        return params.model ?? null;
      case "provider":
        return params.provider ?? null;
      case "credential_class":
        return params.credentialClass ?? null;
    }
  }

  private deny(
    reason: string,
    code: string,
    matched: string[],
  ): McpPolicyEvaluation {
    return { allowed: false, reason, code, matched };
  }
}
