/**
 * RTQ MCP contract-check runner (spec 46.29).
 *
 * CONTRACTS: Every registered MCP tool MUST pass a contract-check before it
 * becomes invocable. The contract-check verifies:
 *   1. Schema completeness (non-incomplete tools only, 46.29 #1).
 *   2. Schema normalization idempotency (re-normalize → same hash, 46.29 #2).
 *   3. Argument validation roundtrip (valid args pass, invalid args reject, 46.29 #3).
 *   4. Declared capability names are well-formed (46.29 #4).
 *   5. Severity is within the permitted range (46.29 #5).
 *
 * FAIL-CLOSED: A tool that fails any check is marked `needsReevaluation: true`
 * and cannot be invoked until re-registered or explicitly re-checked. The
 * registry already denies unregistered tools (46.5); this is a second gate.
 *
 * NOTE: Contract-checks are advisory (they cannot authorize anything), but
 * they MUST be run before the first invocation of any newly-registered tool.
 */

import type {
  McpToolRecord,
  McpSeverity,
} from "./types";
import { McpRegistry } from "./registry";
import { normalizeToolSchema, computeToolSchemaHash, validateToolArguments } from "./schemas";

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** A single check that was performed. */
export interface ContractCheckResult {
  /** Stable identifier for the check (e.g. "schema_completeness"). */
  checkId: string;
  /** Human-readable description. */
  description: string;
  passed: boolean;
  /** Why it failed (empty when passed). */
  reason?: string;
}

/** Aggregate result of all contract checks for a tool. */
export interface ContractCheckReport {
  /** The tool that was checked. */
  serverId: string;
  toolName: string;
  /** All individual check results. */
  checks: ContractCheckResult[];
  /** True when ALL checks passed. */
  passed: boolean;
  /** Timestamp (ms) when the check was run. */
  checkedAt: number;
  /** Schema hash used during the check. */
  schemaHash: string;
}

// ---------------------------------------------------------------------------
// Check functions
// ---------------------------------------------------------------------------

/**
 * 46.29 #1: Schema completeness — an incomplete schema means the tool
 * registered with a degraded or unparseable schema; deny until re-evaluated.
 */
function checkSchemaCompleteness(tool: McpToolRecord): ContractCheckResult {
  const passed = !tool.incomplete;
  return {
    checkId: "schema_completeness",
    description:
      "Tool schema must be fully parsed and non-incomplete (46.29 #1)",
    passed,
    reason: passed ? "" : "Tool registered with incomplete schema",
  };
}

/**
 * 46.29 #2: Normalization idempotency — re-normalizing the raw schema
 * produces the same hash as the stored one.
 */
function checkNormalizationIdempotency(tool: McpToolRecord): ContractCheckResult {
  const reNormalized = normalizeToolSchema(tool.normalizedSchema);
  const reHash = computeToolSchemaHash({
    name: tool.name,
    description: tool.description,
    normalizedSchema: reNormalized.schema,
  });
  const passed = reHash === tool.schemaHash;
  return {
    checkId: "normalization_idempotency",
    description:
      "Re-normalizing the stored schema must produce the same hash (46.29 #2)",
    passed,
    reason: passed
      ? ""
      : `Hash mismatch: stored ${tool.schemaHash} !== recomputed ${reHash}`,
  };
}

/**
 * 46.29 #3: Argument validation — a known-valid argument object passes,
 * and a structurally invalid one is rejected.
 */
function checkArgumentValidation(tool: McpToolRecord): ContractCheckResult {
  // Construct a minimal valid payload: every required field gets a dummy value.
  const validArgs = buildMinimalValidArgs(tool);
  const validResult = validateToolArguments(validArgs, tool.normalizedSchema);
  if (!validResult.valid) {
    return {
      checkId: "argument_validation",
      description:
        "Minimal valid arguments must pass schema validation (46.29 #3)",
      passed: false,
      reason: `Valid args rejected: ${validResult.errors.join("; ")}`,
    };
  }

  // Construct an invalid payload: add a field that should fail.
  const invalidResult = validateToolArguments(
    { __proto__: "pollution", constructor: "nope" },
    tool.normalizedSchema,
  );
  const passed = !invalidResult.valid;
  return {
    checkId: "argument_validation",
    description:
      "Prototype-polluting arguments must be rejected (46.29 #3)",
    passed,
    reason: passed
      ? ""
      : "Prototype-polluting arguments were not rejected",
  };
}

/**
 * 46.29 #4: Capability name well-formedness — if declared, capability names
 * must match the pattern `mcp://<serverId>/<toolName>` or be a plain
 * identifier (alphanumeric + dots + hyphens + underscores).
 */
function checkCapabilityNames(tool: McpToolRecord): ContractCheckResult {
  const capability = tool.capabilityName;
  if (!capability) {
    return {
      checkId: "capability_name",
      description: "Tool must declare a capability name (46.29 #4)",
      passed: false,
      reason: "No capability name declared",
    };
  }
  // Allow mcp:// URIs or plain identifiers.
  const wellFormed =
    capability.startsWith("mcp://") ||
    /^[a-zA-Z0-9._-]+$/.test(capability);
  return {
    checkId: "capability_name",
    description: "Capability name must be well-formed (46.29 #4)",
    passed: wellFormed,
    reason: wellFormed ? "" : `Malformed capability name: "${capability}"`,
  };
}

/**
 * 46.29 #5: Severity range — severity must be one of the known levels.
 */
function checkSeverityRange(tool: McpToolRecord): ContractCheckResult {
  const VALID_SEVERITIES: readonly McpSeverity[] = [
    "low",
    "medium",
    "high",
    "critical",
  ];
  const passed = VALID_SEVERITIES.includes(tool.severity);
  return {
    checkId: "severity_range",
    description: "Severity must be a recognized level (46.29 #5)",
    passed,
    reason: passed ? "" : `Unknown severity: "${tool.severity}"`,
  };
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

const ALL_CHECKS = [
  checkSchemaCompleteness,
  checkNormalizationIdempotency,
  checkArgumentValidation,
  checkCapabilityNames,
  checkSeverityRange,
] as const;

/**
 * Run all contract checks for a single tool. Returns a report and marks
 * `needsReevaluation` on the tool record when any check fails.
 */
export function runContractCheck(
  tool: McpToolRecord,
): ContractCheckReport {
  const checks = ALL_CHECKS.map((fn) => fn(tool));
  const passed = checks.every((c) => c.passed);

  // Mark the tool for re-evaluation if any check fails.
  if (!passed) {
    tool.needsReevaluation = true;
  }

  return {
    serverId: tool.serverId,
    toolName: tool.name,
    checks,
    passed,
    checkedAt: Date.now(),
    schemaHash: tool.schemaHash,
  };
}

/**
 * Run contract checks for ALL tools in a registry. Returns reports for
 * every registered tool.
 */
export function runContractChecksForAll(
  registry: McpRegistry,
): ContractCheckReport[] {
  const reports: ContractCheckReport[] = [];
  for (const server of registry.listServers()) {
    for (const tool of registry.listTools(server.serverId)) {
      reports.push(runContractCheck(tool));
    }
  }
  return reports;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal argument object that should pass schema validation.
 * Maps each required property to a dummy value matching its type.
 */
function buildMinimalValidArgs(tool: McpToolRecord): Record<string, unknown> {
  const schema = tool.normalizedSchema;
  const props = schema.properties as Record<string, unknown> | undefined;
  const required = schema.required as string[] | undefined;
  if (!props || !required) return {};

  const args: Record<string, unknown> = {};
  for (const field of required) {
    const prop = props[field] as Record<string, unknown> | undefined;
    if (!prop) {
      args[field] = "dummy";
      continue;
    }
    const type = prop.type;
    switch (type) {
      case "string":
        args[field] = "dummy";
        break;
      case "number":
      case "integer":
        args[field] = 0;
        break;
      case "boolean":
        args[field] = false;
        break;
      case "array":
        args[field] = [];
        break;
      case "object":
        args[field] = {};
        break;
      default:
        args[field] = "dummy";
    }
  }
  return args;
}
