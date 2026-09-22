# @rtq/mcp

Business-grade **Model Context Protocol** server/tool gateway with RTQ-hosted
security — capability authorization, risk advisory, policy evaluation,
approval tickets, credential isolation, OS sandboxing, contract checks, and a
structured audit trail, §46 of the RTQ spec.

`@rtq/mcp` believes that MCP servers and their tools are **untrusted
third-party code**. Every inbound tool invocation flows through a fail-closed
gateway pipeline — validate → classify → advise → enforce policy → authorize →
execute → normalize — and anything the RTQ operator has not explicitly
approved is **denied**, never guessed.

## What's inside

- **`McpRegistry`** — server + tool registration (1.0) and tool metadata with
  `severity`, transport, tenant/scope, and normalized JSON-Schema input
  schemas. Schemas are hash-pinned (`computeToolSchemaHash`) so tool identity
  is stable across sessions (§46.9, §46.10).
- **`McpRiskAdvisor`** — raise-only, advisory risk classification of a tool
  from RTQ facts + server text. It can only *raise* the operator-assigned
  baseline severity, never lower it; its output feeds policy, it never
  authorizes (§46.14, §46.22–46.26).
- **`McpPolicyEngine`** — fail-closed policy evaluation over effective
  operations (`read`/`write`/`admin`/`network`/`credential`), tenant
  allowlists, transport gates, and RTQ capabilities. Absent policy = deny
  (§46.16–46.21, §46.28).
- **`McpGateway`** — the invoke pipeline: parses arguments against the
  pinned schema hash, issues single-use **ticket bindings** (idempotent,
  non-replayable, tied to server+tool+arguments hash), parks approval-required
  tickets, and executes only under an authorized ticket (§46.5–46.13,
  §46.19–46.20).
- **`McpCredentialVault`** — credentials are stored in RTQ's credential store,
  scoped to resolved classes, and **never returned to the MCP server**; a tool
  requiring a credential class that isn't RTQ-approved fails closed
  (§46.27–46.28).
- **Result normalization** — `normalizeMcpResult` truncates/denies oversized,
  non-JSON, or stack-overflowing results and `normalizeToolSchema` hardens
  tool schemas, including rejecting unsafe keys (`__proto__`, `constructor`) —
  a schema that cannot be mapped safely is marked `incomplete` and the
  gateway fails closed rather than guessing (§46.30 #13–#22).
- **`McpContractCheck` / `runContractCheck`** — schema-completeness and
  hash-determinism invariant checks registered per server+tool (§46.29).
- **Transports** — `McpStdinServerTransport` (stdio) and in-memory transports
  (#46 stdio fail-closed; HTTP is fail-closed by default).
- **`McpRiskAdvice` / `McpSeverity` / `McpEffectiveOperation`** + the policy
  `McpPolicyRule` types used across the matrix.

## Why RTQ-flavored?

RTQ's MCP layer is security-spelled the way the rest of RTQ is: **fail-closed
by default, advisory signals can only raise, and operator facts never come
from server text.** The §46 security matrix (tests/mcp/unit/security-matrix.test.ts)
verifies invariants like:

- unknown servers/tools/effective-operations → denied (§46.30 #1–#7)
- tickets are single-use, non-replayable, bound to args hash (#8–#12)
- schemas with unsafe keys / non-finite numbers are `incomplete` (#13–#17)
- oversized / non-JSON results are denied (#18–#22)
- fail-closed policy + tenant allowlist + transport gate (#23–#27)
- credential isolation: class-bound, never returned to server (#28–#31)
- risk advisory is raise-only, advisory, unclassified default (#32–#35)

## Quick start

```ts
import {
  McpGateway,
  McpRegistry,
  McpPolicyEngine,
  McpRiskAdvisor,
  McpCredentialVault,
  McpStdinServerTransport,
  type McpRiskAdvice,
  type McpSeverity,
} from "@rtq/mcp";

const gateway = new McpGateway({
  registry: new McpRegistry(),
  policy: new McpPolicyEngine({
    rules: [{ instrument: "tool", pattern: "*", allow: false }], // fail-closed
    allowedEffectiveOperations: new Map([
      ["read", ["mcp://*/*"]], // read tools allowed server-wide
    ]),
  }),
  riskAdvisor: new McpRiskAdvisor(),
  credentials: new McpCredentialVault(store), // RTQ credential store (46.27)
  defaultLimits: { maxResultSizeBytes: 64 * 1024 },
});

await gateway.connect("my-server", new McpStdinServerTransport());
// only "read" tools for srv1 are allowed; everything else is denied
```

## API Overview

- Registry & invocation — `McpRegistry`, `computeToolSchemaHash`,
  `normalizeToolSchema`, `normalizeMcpResult`, `validateToolArguments`,
  `normalizeMcpSchema`.
- Risk — `McpRiskAdvisor.advise()`, `classifyEffectiveOperations`,
  `McpRiskAdvice`.
- Policy — `McpPolicyEngine.evaluate()`, `matchesMcpPattern`,
  `McpPolicyRule`.
- Gateway — `McpGateway.invoke()`, ticket system `McpTicket`/`McpTicketBindings`.
- Contracts — `McpContractCheck`, `runContractCheck`.
- Transports — `McpStdinServerTransport`, `McpInMemoryTransport`.

## Security model

- **Fail-closed at every stage.** Unknown server = no session; unknown tool =
  no metadata; unclassified operation = denied; policy absent = deny
  (§46.28 #1–#22, §46.31).
- **Single-use tickets.** `McpGateway` parks an `approvalRequred` ticket and
  never auto-executes; tickets carry the arguments hash for idempotency.
- **Credential isolation (§46.27).** Server tool text cannot bind a
  credential class; only RTQ's resolved credential scope can. The vault never
  hands credentials to the server — it holds `McpRiskAdvice`-shaped facts.
- **Result + schema hardening (§46.30).** Everything the server can hand back
  (results AND schemas) is normalized against RTQ's dialect; anything that
  can't be safely mapped is treated as `incomplete` → deny, never a guess.

## License

Apache-2.0. See [docs/mcp](../../docs/mcp/) for the full §46 spec mapping.
