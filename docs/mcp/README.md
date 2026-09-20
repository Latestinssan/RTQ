# RTQ MCP Integration Layer — `@rtq/mcp`

The `@rtq/mcp` package is RTQ's integration layer for the **Model Context
Protocol** (MCP): connecting to MCP servers, discovering tools, validating
inputs, attacking the result pipeline defensively, and wiring everything into
RTQ's existing authorization boundary.

> **SECURITY INVARIANT:** MCP is an _integration/protocol layer, never an
> authorization boundary._ Everything arriving over an MCP connection — tool
> metadata, descriptions, schemas, resources, prompts, and results — is
> **untrusted data**. RTQ's security decisions are made only by the policy,
> approval, risk, sandbox, and capability-registry components of RTQ, never by
> MCP server input. See [`security.md`](./security.md).

**What MCP tool calls are and are not protected by today (honest status).**
MCP tool calls ARE protected through the full RTQ pipeline: the `McpGateway`
wires every tool invocation through schema validation, effective-operation
classification, advisory risk scoring (raise-only), policy evaluation
(fail-closed), single-use non-replayable authorization tickets, and normalized
result handling with size/depth limits and secret redaction. Credential
isolation stores scoped credentials that are never returned to servers. Local
stdio servers can be OS-sandboxed; when a sandbox is required and unavailable,
the connection fails closed. Contract checks verify schema completeness and
normalization idempotency before any tool becomes invocable.

## Scope

This package implements and tests:

| Concern                                                                | Status                                       |
| ---------------------------------------------------------------------- | -------------------------------------------- |
| JSON-RPC 2.0 wire protocol (parse/build, size limits, strict envelope) | ✅ implemented & tested                      |
| Protocol negotiation (2024-11-05, 2025-06-18)                          | ✅ implemented & tested                      |
| In-memory transport (embedded reference server)                        | ✅ implemented & tested                      |
| stdio transport (local process, optional OS sandbox, fail-closed)      | ✅ implemented & tested                      |
| Streamable-HTTP transport (JSON + SSE, TLS by default)                 | ✅ implemented & tested                      |
| Reference MCP server (for local embedding & contract tests)            | ✅ implemented & tested                      |
| Tool schema normalization & hardening (fail-closed on $ref etc.)       | ✅ implemented & tested                      |
| Result normalization (size/depth limits, redaction, advisory flags)    | ✅ implemented & tested                      |
| Server/tool registration records (trust state, schema hashes, epoch)   | ✅ implemented & tested                      |
| Credential isolation (scoped vault, never returned to server)          | ✅ implemented & tested                      |
| Policy evaluation on MCP calls (fail-closed, transport/tenant gates)   | ✅ implemented & tested                      |
| Risk advisory (raise-only, operation classification)                   | ✅ implemented & tested                      |
| McpGateway (full invoke pipeline: validate→risk→policy→authorize→exec) | ✅ implemented & tested                      |
| Contract-check runner (schema completeness, normalization idempotency) | ✅ implemented & tested                      |
| CLI admin commands (`rtq mcp servers/tools/contracts/revoke/metrics`)  | ✅ implemented                               |
| Observability (metrics snapshot per 46.33)                             | ✅ implemented (in gateway.getMetrics())     |

Legend: ✅ **implemented & tested** (in `tests/mcp/`). No claim of
completeness beyond what the tests prove.

## Package layout

```
packages/mcp/src/
  index.ts        Public API
  types.ts        Domain types (46.6–46.39)
  protocol.ts     JSON-RPC/MCP wire protocol
  transports.ts   In-memory / stdio / HTTP connections
  server.ts       Reference MCP server host
  schemas.ts      Tool schema normalization + validation
  results.ts      Result normalization + redaction + flags
  registry.ts     Server/tool trust records (46.2, 46.5–46.8, 46.11–46.14)
  risk.ts         Risk advisory — raise-only operation classification (46.14, 46.24–46.25)
  policy.ts       Policy engine — fail-closed evaluation on MCP calls (46.16–46.20)
  credentials.ts  Credential vault — scoped storage, never returned to servers
  gateway.ts      McpGateway — full invoke pipeline (46.28–46.33)
  contract.ts     Contract-check runner — schema completeness & normalization (46.29)
```

## Quick start (gateway pipeline)

```ts
import {
  McpGateway, McpRegistry, McpPolicyEngine, McpRiskAdvisor,
  InMemoryConnection, McpReferenceServer,
} from "@rtq/mcp";

// 1. Create the gateway with RTQ-injected authorize/execute callbacks.
const gateway = new McpGateway({
  registry: new McpRegistry(),
  policy: new McpPolicyEngine({
    rules: [{ instrument: "tool", pattern: "mcp://my-server/*", allow: true }],
    allowedEffectiveOperations: new Map([["read", ["mcp://*/*"]]]),
  }),
  riskAdvisor: new McpRiskAdvisor(),
  authorize: async (params) => rtq.authorize(params),
  execute: async (ticketId) => rtq.execute(ticketId),
  tickets: ticketStore,
});

// 2. Connect to a server.
const server = new McpReferenceServer({
  tools: [{ name: "echo", inputSchema: { type: "object" } }],
});
const conn = new InMemoryConnection(server);
const sessionId = await gateway.connect("my-server", conn);

// 3. Discover tools.
const tools = await gateway.discover(sessionId);

// 4. Invoke a tool through the full RTQ pipeline.
const result = await gateway.invoke("my-server", "echo", { msg: "hello" });
// result.status → "executed" | "approval_required" | "denied"
```

Or connect to a remote MCP server over HTTPS:

```ts
import { HttpConnection } from "@rtq/mcp";

const conn = new HttpConnection("https://mcp.example.com/mcp", {
  headers: { authorization: "Bearer <credential-ref>" }, // ref, never inline secret
});
await conn.connect();
```

## Contracts and guarantees

- **Defensive parsing.** Every inbound message passes through
  `parseJsonRpcMessage`: byte-size limit (default 1 MiB), strict envelope
  (unknown fields rejected), strict `jsonrpc: "2.0"`, no partial reads.
- **Fail closed.** Unknown protocol versions, unsupported schema constructs
  (`$ref`, `allOf`, `not`, complex `anyOf`), `additionalProperties: true`,
  tuple-form `items`, unsafe keys (`__proto__`), and non-finite numbers all
  mark the affected tool/schema incomplete; registration fails unless policy
  explicitly approves.
- **Full pipeline on every invocation.** `McpGateway.invoke()` runs:
  schema validation → effective-operation classification → risk advisory
  (raise-only) → policy evaluation (fail-closed) → single-use non-replayable
  authorization ticket → execute → normalize result → audit.
- **Contract checks.** `runContractCheck()` verifies schema completeness,
  normalization idempotency, argument validation, capability name
  well-formedness, and severity range before any tool becomes invocable.
- **Results as data.** Results are truncated or denied by size/depth,
  redacted for secret-shaped values, and annotated with _advisory_ flags for
  injection-like content. Flags never authorize anything.
- **Credential isolation.** Credentials are stored in a scoped vault and
  never returned to MCP servers; the gateway injects them into the transport
  layer only at invocation time.
- **Sandboxed local execution.** stdio servers can run inside the OS sandbox;
  when a sandbox is required and unavailable, the connection fails closed.

## Related docs

- [Security model](./security.md)
- [Configuration](./configuration.md)
- [Capability matrix](./capability-matrix.md)
- [Contract testing](./contract-testing.md)
