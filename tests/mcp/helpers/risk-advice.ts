/**
 * Shared MCP test fixture builders for `tests/mcp/unit`.
 *
 * Kept here so unit tests exercise the *real* production types instead of
 * drifting test-only literals (which previously "passed" at runtime while
 * failing `tsc --noEmit` in CI — §46.30 typecheck gate).
 */
import type {
  McpEffectiveOperation,
  McpRiskAdvice,
  McpSeverity,
} from "../../../packages/mcp/src/index";

/**
 * Build a valid, fail-closed-shaped `McpRiskAdvice` from the minimal facts a
 * test wants to express.
 *
 * Maps the legacy `{ severity, effectiveOperations, riskContributions }`
 * test literal onto the real `McpRiskAdvice` shape (`baseline`/`effective`,
 * `contributions`, plus the advisory booleans). `effectiveOperations` drives
 * the policy engine's effective-operation gate (46.25); everything else is
 * non-raising advisory metadata.
 */
export function mcpAdvice(
  severity: McpSeverity,
  effectiveOperations: readonly McpEffectiveOperation[] = ["read"],
  extra: Partial<
    Pick<McpRiskAdvice, "appearsIrreversible" | "requiresNetwork">
  > = {},
): McpRiskAdvice {
  return {
    baseline: severity,
    effective: severity,
    contributions: [],
    effectiveOperations,
    appearsIrreversible: extra.appearsIrreversible ?? false,
    requiresNetwork: extra.requiresNetwork ?? false,
    unclassified: false,
  };
}
