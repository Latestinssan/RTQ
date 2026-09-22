# @rtq/risk

**Advisory (never authorizing) risk facts for the RTQ §46 gateway.** The risk
engine and advisor classify *advisory* severity and effective operations for
every tool/argument the pipeline sees. Advisory is **raise-only**: it can only
raise the operator baseline severity, never lower it, and it *never* authorizes
anything — policy and the registry own that. An un-classifiable tool stays
`unclassified` (deny-by-default at policy) rather than guessing.

## What's inside

- **`McpRiskAdvisor`** (`advise`) — operator-baseline + tool text →
  `McpRiskAdvice` with `baseline`, `effective` (baseline + advisory
  contributions, capped), `appearsIrreversible`, `requiresNetwork`,
  `unclassified`. Advisory cannot lower `baseline` (§46.25).
- **`McpRiskAdvisorOptions`** — `baselineSeverity`, overrides, hardcoded-risk
  prefix rules.
- **`McpRiskAdvice`**, **`McpRiskContribution`** — the advisory record shape
  (`factor`, `detail`, `raisesBy`) that policy consumes.
- **`McpSeverity`, `McpRiskSignal`, `McpRiskFactor`** — `low|medium|high|
  critical` severity + signal/factor kinds (§46.24–46.25).
- **`classifyEffectiveOperations`** (+ `McpEffectiveOperation`) — maps a
  tool's name/description onto `read|write|admin|system|network|credential|
  unknown`. **`unknown` is deliberately NOT auto-raised**; it stays
  `unknown` so policy fails closed (§46.11, §46.28 #6).
- **`credentialClassSignal`** — only raises when the tool reads/writes a
  credential class (admin/write credential ops), never for plain tool text.

## Example

```ts
import { McpRiskAdvisor } from "@rtq/risk";

const advisor = new McpRiskAdvisor({ baselineSeverity: "low" });
const advice = advisor.advise("low", undefined, {
  name: "mcp://srv1/delete_all",
  description: "Irreversibly delete all rows",
});

advice.effectiveOperations; // => ["write"]   (delete_all => irreversible)
advice.effective;           // => "medium"    ("low" + irreversible=+1, capped)
```

## Advisory only — never authorization

RTQ's risk engine is strictly advisory (§46). It can only tell policy "this
looks risky / irreversible / network-reaching". The **policy engine** and the
**registry** are the only RTQ components that may *deny* or *allow*; for a
tool that's `unknown`, policy on RTQ denies by default even if some other
component's text says "safe". Operator facts and risk facts can only raise
severity, and an advisory that can only raise is safe to render in tickets
(§46.25–46.32). This is the "advisory, raise-only" invariant — test
`tests/mcp/unit/risk.test.ts` proves the advisor can never *lower* baseline,
and `security-matrix` §46 #32–#35 proves raise-only + unclassified-default.

## Related

- `@rtq/policy` — the *only* component that authorizes (or denies).
- `@rtq/mcp` — gateway consumes this package to build `McpRiskAdvice` for
  every invocation (§46.14 pipeline step).

## License

Apache-2.0
