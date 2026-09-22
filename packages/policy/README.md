# @rtq/policy

**Fail-closed policy engine for RTQ §46.** Declarative rules that transform a
tool/server/effort-riding RTQ capability into an **allow / deny / override /
approval-required** decision, with deny-first best-match-wins and an
"unmatched ⇒ deny" default (§46.16–46.21, §46.28 #6, §46.30 #23–#27).

## What's inside

- `McpPolicyEngine` / `McpPolicyEngineOptions` — evaluate a capability against
  operator-declared rules: `AllowRule` / `DenyRule` / `OverrideRule` /
  `ApprovalRule` (+ `PolicyCondition` for tenant/resource/model gates).
- `McpPolicyRule` / `McpPolicyEvaluation` — a rule's instrument + pattern +
  `allow` + optional `scopeId`/`tenant`, and the result with `allowed`,
  `reason`, and the matched rule trail.
- `matchesMcpPattern` — `*`-globbing used by the engine (fail-closed on
  patterns that can't be proven).
- `McpPolicyEngine.evaluate` takes `riskAdvice?: McpRiskAdvice` — the risk
  advisor's advisory signal (§46 risk). RTQ's policy can only **deny more**,
  never authorize (§46.16 #2); if `riskAdvice.effectiveOperations` contains an
  operation that has no allow-list coverage, evaluation **denies** (§46.28 #6).

## Quick start

```ts
import { McpPolicyEngine } from "@rtq/policy";

const engine = new McpPolicyEngine({
  rules: [{ instrument: "tool", pattern: "mcp://srv1/*", allow: false }],
  allowedEffectiveOperations: new Map([["read", ["mcp://*/*"]]]),
});

const r = engine.evaluate({
  capabilityName: "mcp://srv1/delete_all",
  serverId: "srv1",
  toolName: "delete_all",
  riskAdvice: { baseline: "low", effective: "low", effectiveOperations: ["read"], contributions: [] },
});
// r.allowed === false  (tool pattern denied by rule)
```

## Security posture

- **Fail-closed**: no matching rule, unknown operation, unknown tenant →
  deny. An empty rule set denies everything.
- **Deny-first, best-match**: the most specific matching rule wins; an
  explicit deny beats any allow for the same target.
- **Risk is advisory-on**: `evaluate` never upgrades an allowed→denied from
  friendlier operations, and never fabricates an allow from server text.

## Used by

`@rtq/mcp` (`McpGateway` policy stage), `@rtq/security` (pipeline §46.16),
`@rtq/cli` (`rtq mcp policy`).

## License

Apache-2.0
