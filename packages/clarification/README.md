# @rtq/clarification

Business-grade clarification engine for the RTQ pipeline: it turns
**execution-time ambiguity** — the tool/workflow asking *"which do you mean?"* —
into a first-class, auditable, fail-closed decision point instead of a silent
guess.

`@rtq/clarification` handles the case where RTQ capabilities are just ambiguous
enough that RTQ *cannot* classify risk, policy, or authorization for them. RTQ's
invariant (§ spec) is: **never guess on ambiguity.** If a tool's effective
operation or requested scope can't be unambiguously determined, RTQ parks the
invocation and asks back rather than running it.

## What it does

- **`ClarificationEngine`** — given a tool/workflow description and the facts
  RTQ knows, decides whether the invocation is unambiguous (proceed), asks for
  the missing disambiguation (clarify), or denies when the ambiguity can't be
  resolved from available facts (fail closed).
- **`ClarificationRule`** — lets operators declare what "asked for" means for an
  instrument per this package's rule engine, enabling per-server/per-tool
  clarification policy instead of a global heuristic.
- **Fail-closed by default.** No configured rule = the baseline classification
  applies; unknown/undeterminable operation = denied (§46 #43 clarification
  deny, §46 #54–#56 normalization gates).

## Install

```sh
npm install @rtq/clarification
```

## Quick start

```ts
import { ClarificationEngine } from "@rtq/clarification";

const engine = new ClarificationEngine({
  // Operator-declared clarification rules; absent = base behavior
  rules: [
    { instrument: "tool", pattern: "mcp://srv1/*", askWhenAmbiguous: true },
  ],
});

const verdict = engine.classify({
  capabilityName: "mcp://srv1/read_file",
  serverId: "srv1",
  toolName: "read_file",
  description: "Read the named file",
  // RTQ fact: only "read" is classify-able from the description
  effectiveOperations: ["read"],
});
// Unambiguous → { requireClarification: false, reason: "classification unambiguous" }
```

## Security posture

All classification in this package **fails closed**:

- an operation that cannot be unambiguously classified is treated as
  "unclassified" → for RTQ, **deny**, never a guess;
- server-provided text can only *raise* advisory ambiguity, never lower it;
- no rule, no ambiguity resolution = the operator baseline applies unchanged.

## Related

Used by `@rtq/mcp` and `@rtq/risk` for the §46 MCP integration layer
(risk-aware classification, policy bracket).

## License

Apache-2.0
