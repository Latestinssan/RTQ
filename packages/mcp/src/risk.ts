/**
 * MCP risk advisor (spec 46.10, 46.14, 46.15, 46.28 #2, 46.25).
 *
 * SCOPE: RTQ owns the AUTHORITATIVE risk number. This advisor only produces a
 * policy-friendly ADVISORY classification that can only ever RAISE risk — it
 * never lowers it. The gateway feeds the advisory into RTQ capability risk
 * factors; RTQ's RiskEngine remains the sole decider that maps factors to a
 * final authorization-time risk level. A tool that the advisor flags as risky
 * can still be approved by an operator; a tool RTQ marks high-risk cannot be
 * downgraded by this advisor.
 *
 * Advisory inputs (never trusted from the server):
 *   - operator-assigned `severity` (McpServerRecord.toolSeverity /
 *     defaultSeverity) — the RTQ-decided baseline,
 *   - RTQ facts about the server: transport, identity verification state,
 *     credential class, sandbox, tenant scope, resource scope,
 *   - operator policy: whether network I/O is reverting on an irreversible
 *     path, which resource scopes are sensitive, which credential classes
 *     gate write/admin operations.
 *
 * Advisory verbs (46.25 effective operations) map onto RTQ operation classes
 * (`read`/`write`/`admin`/`system`/`network`/`credential`) so the gateway can
 * match them against the RTQ capability policy surface.
 */
import type {
  McpCredentialClass,
  McpOriginKind,
  McpSecurityContext,
  McpSeverity,
} from "./types";

/** Operation classes RTQ binds to a tool's effective authorization (46.25). */
export type McpEffectiveOperation =
  | "read"
  | "write"
  | "admin"
  | "system"
  | "network"
  | "credential"
  | "unknown";

/** One advisory risk contribution for audit + clarification rendering. */
export interface McpRiskContribution {
  factor: string;
  detail: string;
  /** Amount this contribution ADDS to the effective severity (0–2). */
  raisesBy: number;
}

export interface McpRiskAdvice {
  /** Baseline severity (RTQ/operator fact) — never raised by server text. */
  baseline: McpSeverity;
  /** Effective advisory severity = baseline raised by contributions, capped. */
  effective: McpSeverity;
  /** The single strongest reason, for human approval screens. */
  strongestReason?: string;
  contributions: readonly McpRiskContribution[];
  /** Effective operation classes this tool maps to (46.25). */
  effectiveOperations: readonly McpEffectiveOperation[];
  /** Advisory: does this tool appear to make progress irreversible? */
  appearsIrreversible: boolean;
  /** Advisory: does this tool reach the network? */
  requiresNetwork: boolean;
  /** True when no advisory signal is present and the baseline applies. */
  unclassified: boolean;
}

const SEVERITY_RANK: Readonly<Record<McpSeverity, number>> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

const SEVERITY_FROM_RANK: readonly McpSeverity[] = [
  "low",
  "medium",
  "high",
  "critical",
];

function clampSeverity(base: number, delta: number): McpSeverity {
  const rank = Math.min(
    3,
    Math.max(0, base + delta),
  );
  return SEVERITY_FROM_RANK[rank];
}

export function getEffectiveOperations(
  signals: {
    name: string;
    description?: string;
    tokens?: readonly string[];
    declaredCapabilities?: readonly string[];
  },
  opts?: { transport?: string; identityVerified?: boolean },
): readonly McpEffectiveOperation[] {
  const res = classifyEffectiveOperations(undefined, signals, opts?.transport);
  return res.operations;
}

/**
 * Deterministic heuristic classifier over a tool's effective operation. Based
 * on normalized token patterns, NOT on server free text — it can only ever
 * raise effective severity and is advisory only.
 */
export function classifyEffectiveOperations(
  ctx: McpSecurityContext | undefined,
  signals: {
    name: string;
    description?: string;
    /** RTQ-normalized tool metadata keywords (description, declared caps). */
    tokens?: readonly string[];
    declaredCapabilities?: readonly string[];
  },
  transportOverride?: string,
): {
  operations: readonly McpEffectiveOperation[];
  appearsIrreversible: boolean;
  requiresNetwork: boolean;
  strongestReason?: string;
} {
  const tokens = signals.tokens ?? extractTokens(signals.name, signals.description);
  const operations = new Set<McpEffectiveOperation>(["unknown"]);
  let appearsIrreversible = false;
  let requiresNetwork = false; // advisories default false; transports raise below

  // Transport is an RTQ fact, never a server fact: http/remote transports are
  // always network-reach-relevant (46.15).
  const transport = transportOverride;
  if (transport === "http" || transport === "stdio") {
    // stdio is local spawn; it does not imply remote network. Only http implies
    // network reach in the advisory. Explicit separate network signals handled
    // via declared capabilities.
    if (transport === "http") requiresNetwork = true;
  }

  if (signals.declaredCapabilities?.some((c) => /network|fetch|http/i.test(c))) {
    requiresNetwork = true;
    operations.add("network");
  }

  // Irreversibility advisory (46.14): destructive/delete/reset verbs.
  if (hasToken(tokens, /^(delete|remove|unlink|destroy|reset|drop|clear|overwrite|truncate|shutdown|reboot|restart)$/)) {
    appearsIrreversible = true;
    operations.add("write");
  } else if (hasToken(tokens, /^(write|create|put|post|insert|update|patch|set|append|upload|send)$/)) {
    operations.add("write");
  } else if (hasToken(tokens, /^(read|get|list|query|describe|search|inspect|fetch|peek)$/)) {
    operations.add("read");
  }

  // Credential/admin advisory.
  if (hasToken(tokens, /^(grant|revoke|rotate|issue|sign|approve|authorize|admin|suspend|block)$/)) {
    operations.add("admin");
    operations.add("credential");
  }

  // Remove the fallback "unknown" when a specific operation was classified.
  // "unknown" is only retained when no other heuristic matched (fail-closed).
  if (operations.size > 1) {
    operations.delete("unknown");
  }

  // Default stays "unknown" (fail closed at authorization unless policy maps it).
  return {
    operations: [...operations],
    appearsIrreversible,
    requiresNetwork,
    strongestReason: appearsIrreversible
      ? "strongly_irreversible"
      : requiresNetwork
        ? "network_reach"
        : undefined,
  };
}

function extractTokens(
  name: string,
  description?: string,
): readonly string[] {
  const source = `${name} ${description ?? ""}`;
  return source
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 0);
}

function hasToken(tokens: readonly string[], re: RegExp): boolean {
  return tokens.some((t) => re.test(t));
}

/**
 * McpRiskAdvisor — the MCP gateway's advisory risk surface.
 *
 * It turns (server record + tool record + security context) into an advisory
 * `McpRiskAdvice` that the gateway converts to RTQ risk factors. It is the
 * ONLY place in the MCP layer allowed to look at tool names/descriptions, and
 * it does so ONLY to raise risk, never to lower it and never to authorize.
 */
export class McpRiskAdvisor {
  constructor(
    private readonly classify: typeof classifyEffectiveOperations = classifyEffectiveOperations,
  ) {}

  /** Advisory severity for a tool given its operator baseline + contextual
   *  signals. Baseline comes from the record, never from the server. */
  advise(
    baseline: McpSeverity,
    ctx: McpSecurityContext | undefined,
    signals: Parameters<typeof classifyEffectiveOperations>[1],
    options?: { identityVerified?: boolean },
  ): McpRiskAdvice {
    const classified = this.classify(ctx, signals);
    const contributions: McpRiskContribution[] = [];
    let delta = 0;

    // Operation correctness: unknown → raise. Operators can still approve, but
    // RTQ's fail-closed default stands until then.
    if (
      classified.operations.length === 1 &&
      classified.operations[0] === "unknown"
    ) {
      delta = Math.max(delta, 1);
      contributions.push({
        factor: "effective_operation_unclassified",
        detail: "Tool does not map to a known effective operation class",
        raisesBy: 1,
      });
    }

    if (classified.appearsIrreversible) {
      delta = Math.max(delta, 1);
      contributions.push({
        factor: "appears_irreversible",
        detail: "Tool name/claims suggest a destructive or reset operation",
        raisesBy: 1,
      });
    }

    if (classified.requiresNetwork) {
      delta = Math.max(delta, 1);
      contributions.push({
        factor: "network_reach",
        detail: "Tool reaches the network (remote transport or capability)",
        raisesBy: 1,
      });
    }

    // Credential-class advisory: if the effective operation includes credential
    // or admin, treat the baseline as high.
    if (
      classified.operations.includes("credential") ||
      classified.operations.includes("admin")
    ) {
      delta = Math.max(delta, 1);
      contributions.push({
        factor: "credential_adjacent",
        detail: "Effective operation touches credentials or administrative state",
        raisesBy: 1,
      });
    }

    // Identity verification is an RTQ fact: an unverified server raises the
    // advisory (46.14).
    if (options?.identityVerified === false) {
      delta = Math.max(delta, 1);
      contributions.push({
        factor: "identity_unverified",
        detail: "Server identity material not independently verified",
        raisesBy: 1,
      });
    }

    const effective = clampSeverity(SEVERITY_RANK[baseline], delta);
    const sorted = [...contributions].sort((a, b) => b.raisesBy - a.raisesBy);
    return {
      baseline,
      effective,
      strongestReason: sorted[0]?.factor,
      contributions: sorted,
      effectiveOperations: classified.operations,
      appearsIrreversible: classified.appearsIrreversible,
      requiresNetwork: classified.requiresNetwork,
      unclassified:
        classified.operations.length === 1 &&
        classified.operations[0] === "unknown",
    };
  }
}

/** Map a resolved credential class onto an advisory severity delta (advisory
 *  only; RTQ still decides). */
export function credentialClassSignal(
  credentialClass: McpCredentialClass | undefined,
): { factor: string; delta: number } | undefined {
  if (!credentialClass) return undefined;
  if (credentialClass === "admin") {
    return { factor: "credential_class_admin", delta: 1 };
  }
  if (credentialClass === "write") {
    return { factor: "credential_class_write", delta: 1 };
  }
  return undefined;
}
