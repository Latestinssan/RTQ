import type {
  ApprovalStrategy,
  ClarificationQuestion,
  Origin,
  PolicyDecision,
  RiskLevel,
} from "@rtq/core";

/** Simple glob matcher for capability names: `*` and `**` supported. */
export function globToRegExp(glob: string): RegExp {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^.]*")
    .replace(/\u0000/g, ".*");
  return new RegExp(`^${escaped}$`);
}

export interface PolicyCondition {
  /** Resource path prefix that must match the operation target (normalized). */
  path?: string;
  /** Origin(s) that must match (if omitted, any origin matches). */
  origin?: Origin | readonly Origin[];
  /** Lower bound on the CURRENTLY EVALUATED risk. */
  riskAtLeast?: RiskLevel;
  /** Input field constraint. */
  field?: { name: string; eq?: unknown; exists?: boolean };
}

export interface PolicyRuleBase {
  /** Capability glob, e.g. "filesystem.delete" or "tools.**". */
  capability: string;
  /** Optional conditions. All specified conditions must match. */
  when?: PolicyCondition;
  /** Free-form rationale (recorded in audit). */
  reason: string;
}

export interface DenyRule extends PolicyRuleBase {
  kind: "deny";
  code: string;
}

export interface AllowRule extends PolicyRuleBase {
  kind: "allow";
  /** Force the evaluated risk level UP to this level (never below current). */
  risk?: RiskLevel;
}

export interface OverrideRule extends PolicyRuleBase {
  kind: "override";
  /** Set/raise the evaluation risk to this level. */
  risk: RiskLevel;
}

export interface ApprovalRule extends PolicyRuleBase {
  kind: "requireApproval" | "requireVerification" | "requireClarification";
  strategy?: ApprovalStrategy;
  questions?: ClarificationQuestion[];
}

export type PolicyRule = DenyRule | AllowRule | OverrideRule | ApprovalRule;

export interface PolicyEvaluation {
  decision: PolicyDecision;
  matchedRules: string[];
  policyVersion: string;
}

export interface PolicyEngineOptions {
  /**
   * When no rule matches an operation, the default is DENY (secure default).
   * Set to 'allow' ONLY as an explicit, documented relaxation; even then the
   * capability's own approval requirement still applies downstream.
   */
  defaultMode?: "deny" | "allow";
  policyVersion?: string;
}

function matchesCondition(
  condition: PolicyCondition | undefined,
  ctx: ConditionContext,
): boolean {
  if (!condition) return true;
  if (condition.origin !== undefined) {
    const allowed = Array.isArray(condition.origin)
      ? condition.origin
      : [condition.origin];
    if (!allowed.includes(ctx.origin)) return false;
  }
  if (condition.path !== undefined) {
    const resource = ctx.resource ?? "";
    const normResource = normalizePath(resource);
    const normPrefix = normalizePath(condition.path);
    if (!normResource.startsWith(normPrefix)) return false;
  }
  if (condition.riskAtLeast !== undefined) {
    if (rank(ctx.risk) < rank(condition.riskAtLeast)) return false;
  }
  if (condition.field !== undefined) {
    const value = ctx.input[condition.field.name];
    if (condition.field.exists === true && value === undefined) return false;
    if (condition.field.eq !== undefined && value !== condition.field.eq)
      return false;
  }
  return true;
}

function normalizePath(p: string): string {
  return p.replace(/[\\/]+/g, "/").replace(/\/+$/, "");
}

function rank(level: RiskLevel): number {
  const order: Record<RiskLevel, number> = {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3,
  };
  return order[level] ?? 0;
}

export interface ConditionContext {
  capability: string;
  input: Record<string, unknown>;
  origin: Origin;
  risk: RiskLevel;
  resource?: string;
}

/**
 * Declarative policy engine.
 *
 * Order of precedence:
 *   1. deny rules (any match -> DENY)
 *   2. requireClarification rules -> clarification_required
 *   3. requireApproval / requireVerification rules -> approval_required
 *   4. allow rules -> allowed (with risk override applied)
 *   5. override rules -> applied only in combination with allow
 *   6. no match -> defaultMode (deny by default)
 */
export class PolicyEngine {
  private readonly rules: PolicyRule[] = [];
  private readonly defaultMode: "deny" | "allow";
  readonly policyVersion: string;

  constructor(options: PolicyEngineOptions = {}) {
    this.defaultMode = options.defaultMode ?? "deny";
    this.policyVersion = options.policyVersion ?? "policy-v1";
  }

  add(rule: PolicyRule): void {
    this.rules.push(rule);
  }

  /** Fluent API: deny(...) */
  deny(
    capability: string,
    when: PolicyCondition | undefined,
    opts: { code: string; reason: string },
  ): DenyRule {
    const rule: DenyRule = {
      kind: "deny",
      capability,
      when,
      reason: opts.reason,
      code: opts.code,
    };
    this.add(rule);
    return rule;
  }

  /** Fluent API: allow(...) */
  allow(
    capability: string,
    when: PolicyCondition | undefined,
    opts: { reason: string; risk?: RiskLevel },
  ): AllowRule {
    const rule: AllowRule = {
      kind: "allow",
      capability,
      when,
      reason: opts.reason,
      risk: opts.risk,
    };
    this.add(rule);
    return rule;
  }

  /** Fluent API: override risk for a capability/condition. */
  override(
    capability: string,
    when: PolicyCondition | undefined,
    opts: { reason: string; risk: RiskLevel },
  ): OverrideRule {
    const rule: OverrideRule = {
      kind: "override",
      capability,
      when,
      reason: opts.reason,
      risk: opts.risk,
    };
    this.add(rule);
    return rule;
  }

  /** Fluent API: requireApproval(...) */
  requireApproval(
    capability: string,
    when: PolicyCondition | undefined,
    opts: { reason: string; strategy?: ApprovalStrategy },
  ): ApprovalRule {
    const rule: ApprovalRule = {
      kind: "requireApproval",
      capability,
      when,
      reason: opts.reason,
      strategy: opts.strategy,
    };
    this.add(rule);
    return rule;
  }

  /** Fluent API: requireVerification(...) (device-bound approval) */
  requireVerification(
    capability: string,
    when: PolicyCondition | undefined,
    opts: { reason: string; strategy?: ApprovalStrategy },
  ): ApprovalRule {
    const rule: ApprovalRule = {
      kind: "requireVerification",
      capability,
      when,
      reason: opts.reason,
      strategy: opts.strategy ?? "device_verification",
    };
    this.add(rule);
    return rule;
  }

  /** Fluent API: requireClarification(...) */
  requireClarification(
    capability: string,
    when: PolicyCondition | undefined,
    opts: { reason: string; questions: ClarificationQuestion[] },
  ): ApprovalRule {
    const rule: ApprovalRule = {
      kind: "requireClarification",
      capability,
      when,
      reason: opts.reason,
      questions: opts.questions,
    };
    this.add(rule);
    return rule;
  }

  /** Evaluate an operation against the rule set. */
  evaluate(ctx: ConditionContext): PolicyEvaluation {
    const matchedRules: string[] = [];
    // Compile each rule's glob once per evaluation and test it against the
    // capability being authorized. (Compiling the requested capability and
    // matching it against the rule's glob inverts the relationship and makes
    // every glob rule fail to match.)
    const globCache = new Map<string, RegExp>();
    const regexFor = (glob: string): RegExp => {
      let re = globCache.get(glob);
      if (!re) {
        re = globToRegExp(glob);
        globCache.set(glob, re);
      }
      return re;
    };

    const application = (rule: PolicyRule): boolean =>
      regexFor(rule.capability).test(ctx.capability) &&
      matchesCondition(rule.when, ctx);

    // 1. Deny wins.
    for (const rule of this.rules) {
      if (rule.kind === "deny" && application(rule)) {
        matchedRules.push(`deny:${rule.capability}`);
        return {
          decision: { decision: "deny", reason: rule.reason, code: rule.code },
          matchedRules,
          policyVersion: this.policyVersion,
        };
      }
    }

    // 2. Clarification.
    for (const rule of this.rules) {
      if (rule.kind === "requireClarification" && application(rule)) {
        matchedRules.push(`clarify:${rule.capability}`);
        return {
          decision: {
            decision: "clarification_required",
            reason: rule.reason,
            questions: rule.questions ?? [],
          },
          matchedRules,
          policyVersion: this.policyVersion,
        };
      }
    }

    // 3. Approval required.
    for (const rule of this.rules) {
      if (
        (rule.kind === "requireApproval" ||
          rule.kind === "requireVerification") &&
        application(rule)
      ) {
        matchedRules.push(`${rule.kind}:${rule.capability}`);
        return {
          decision: {
            decision: "approval_required",
            strategy: rule.strategy ?? "user_confirmation",
            reason: rule.reason,
          },
          matchedRules,
          policyVersion: this.policyVersion,
        };
      }
    }

    // 4. Allow (with optional risk raise).
    let finalRiskOverride: RiskLevel | undefined;
    for (const rule of this.rules) {
      if (rule.kind === "allow" && application(rule)) {
        matchedRules.push(`allow:${rule.capability}`);
        if (rule.risk !== undefined && rank(rule.risk) > rank(ctx.risk)) {
          finalRiskOverride = rule.risk;
        }
        break;
      }
    }
    if (finalRiskOverride !== undefined) {
      return {
        decision: {
          decision: "allow",
          reason: "policy allow (risk raised to " + finalRiskOverride + ")",
          overrides: { risk: finalRiskOverride },
        },
        matchedRules,
        policyVersion: this.policyVersion,
      };
    }
    if (matchedRules.some((m) => m.startsWith("allow:"))) {
      return {
        decision: { decision: "allow", reason: "policy allow" },
        matchedRules,
        policyVersion: this.policyVersion,
      };
    }

    // 5. Override rules only take effect combined with an allow; without one
    // they cannot create an allowance. Record and continue.
    for (const rule of this.rules) {
      if (rule.kind === "override" && application(rule)) {
        matchedRules.push(`override:${rule.capability}`);
      }
    }

    // 6. Default (deny by default).
    if (this.defaultMode === "allow") {
      return {
        decision: { decision: "allow", reason: "policy defaultMode=allow" },
        matchedRules,
        policyVersion: this.policyVersion,
      };
    }
    return {
      decision: {
        decision: "deny",
        reason: "no matching policy rule (default deny)",
        code: "policy.default_deny",
      },
      matchedRules,
      policyVersion: this.policyVersion,
    };
  }

  get rulesSnapshot(): readonly PolicyRule[] {
    return [...this.rules];
  }
}
