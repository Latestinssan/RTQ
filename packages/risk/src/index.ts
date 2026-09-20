import {
  maxRisk,
  raiseRisk,
  type Origin,
  type RiskCapabilityFactors,
  type RiskEvaluation,
  type RiskLevel,
} from "@rtq/core";

/**
 * Risk evaluation context — never anything the caller controls for
 * downgrading. The caller-supplied `claimedRisk` (if present at all) is
 * ignored entirely: risk is derived from trusted declarative inputs and
 * observed operation context, and can only RAISE from the capability base.
 */
export interface RiskContext {
  /** Effective origin after policy resolution. Unknown is never treated as local. */
  origin?: Origin;
  /** Reversibility of the operation (false => irreversible => riskier). */
  reversible?: boolean;
  /** Data sensitivity class touched by the operation. */
  dataSensitivity?: "none" | "personal" | "secret" | "critical";
  /** Whether the operation has direct financial impact. */
  financialImpact?: boolean;
  /** Whether the operation changes privileges (grants, tokens, DACL, ...). */
  privilegeImpact?: boolean;
  /** Whether the capability will use the network. */
  requiresNetwork?: boolean;
  /** Whether the operation touches system configuration. */
  touchesSystem?: boolean;
  /** Resource selector (e.g. a filesystem path) used for prefix matching. */
  resource?: string;
}

export interface RiskEngineOptions {
  /**
   * Origin escalation steps (default: remote/mobile/plugin/agent/automation
   * +1, unknown +1 — NEVER treated as local).
   */
  originEscalation?: Partial<Record<Origin, number>>;
  /**
   * Resource prefixes (filesystem-style) that raise risk when the operation
   * targets them. Configurable per deployment.
   */
  sensitiveResourcePrefixes?: readonly string[];
  /** Policy version recorded in every evaluation. */
  policyVersion?: string;
}

const DEFAULT_ORIGIN_ESCALATION: Record<Origin, number> = {
  local: 0,
  remote: 1,
  mobile: 1,
  plugin: 1,
  agent: 1,
  automation: 1,
  unknown: 1,
};

const DEFAULT_SENSITIVE_PREFIXES = [
  "/etc/",
  "/usr/",
  "/System/",
  "/Library/",
  "/private/etc/",
  "C:\\Windows\\",
];

export class RiskEngine {
  private readonly originEscalation: Record<Origin, number>;
  private readonly sensitivePrefixes: readonly string[];
  readonly policyVersion: string;

  constructor(options: RiskEngineOptions = {}) {
    this.originEscalation = {
      ...DEFAULT_ORIGIN_ESCALATION,
      ...options.originEscalation,
    };
    this.sensitivePrefixes =
      options.sensitiveResourcePrefixes ?? DEFAULT_SENSITIVE_PREFIXES;
    this.policyVersion = options.policyVersion ?? "risk-v1";
  }

  /**
   * Evaluate the AUTHORITATIVE risk for an operation. The `claimedRisk` from
   * an untrusted caller is never consulted; supplying it here is at most a
   * candidate that can only be RAISED to, never used to lower the result.
   */
  evaluate(
    base: RiskCapabilityFactors,
    baseLevel: RiskLevel,
    context: RiskContext = {},
    claimedRisk?: RiskLevel,
  ): RiskEvaluation {
    const contributions: RiskEvaluation["contributions"] = [];
    const startLevel: RiskLevel =
      baseLevel === "critical"
        ? "critical"
        : claimedRisk
          ? maxRisk(baseLevel, claimedRisk)
          : baseLevel;
    let level = startLevel;

    // Origin: unknown is never local. If no origin is given, treat as local
    // for BASE evaluation but NEVER accept an explicit 'unknown' as local.
    const origin = context.origin ?? "local";
    const escalation = this.originEscalation[origin] ?? 0;
    if (origin === "unknown") {
      contributions.push({
        factor: "origin",
        detail: "origin is unknown; treated as untrusted (escalated)",
      });
      level = raiseRisk(level, 1);
    } else if (escalation > 0) {
      contributions.push({
        factor: "origin",
        detail: `origin "${origin}" escalates risk by ${escalation} step(s)`,
      });
      level = raiseRisk(level, escalation);
    }

    if (context.reversible === false) {
      contributions.push({
        factor: "reversibility",
        detail: "operation is irreversible",
      });
      level = raiseRisk(level, 1);
    }

    switch (context.dataSensitivity) {
      case "personal":
        contributions.push({
          factor: "data-sensitivity",
          detail: "touches personal data",
        });
        level = raiseRisk(level, 1);
        break;
      case "secret":
        contributions.push({
          factor: "data-sensitivity",
          detail: "touches secret data",
        });
        level = raiseRisk(level, 1);
        break;
      case "critical":
        contributions.push({
          factor: "data-sensitivity",
          detail: "touches critical data",
        });
        level = raiseRisk(level, 2);
        break;
      default:
        break;
    }

    if (context.financialImpact) {
      contributions.push({
        factor: "financial-impact",
        detail: "direct financial impact",
      });
      level = raiseRisk(level, 1);
    }
    if (context.privilegeImpact) {
      contributions.push({
        factor: "privilege-impact",
        detail: "changes privileges",
      });
      level = raiseRisk(level, 1);
    }
    if (context.requiresNetwork) {
      contributions.push({
        factor: "network",
        detail: "operation requires network access",
      });
      level = raiseRisk(level, 1);
    }
    if (context.touchesSystem) {
      contributions.push({
        factor: "system",
        detail: "touches system configuration",
      });
      level = raiseRisk(level, 1);
    }

    const resource = context.resource;
    if (resource && typeof resource === "string") {
      const norm = resource.replace(/[\\/]+/g, "/");
      const hit = this.sensitivePrefixes.find((p) => {
        const normPrefix = p.replace(/[\\/]+/g, "/");
        return norm.startsWith(normPrefix);
      });
      if (hit) {
        contributions.push({
          factor: "resource",
          detail: `resource matches sensitive prefix "${hit}"`,
        });
        level = raiseRisk(level, 1);
      }
    }

    return {
      level,
      baseLevel,
      contributions,
      policyVersion: this.policyVersion,
    };
  }
}
