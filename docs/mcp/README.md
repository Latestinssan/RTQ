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
MCP tool calls ARE protected through the hygiene and enforcement layers that
this package already implements and tests: strict schema/result
normalization, fail-closed registration of unknown/unsafe schemas, result
redaction and size/depth limiting, and (for local stdio servers) OS-sandboxed
execution that fails closed. They are NOT yet protected by RTQ's policy
evaluation, risk scoring, or human-approval gating on the tool call itself —
those components exist as tested packages, but wiring them onto the MCP
tool-call path is still **planned, not started** (see the capability matrix's
"Planned" rows). In other words: this layer keeps MCP *data* safe; the
decision-making that authorizes MCP *actions* is not yet connected here.

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
| Credential isolation (credential refs, never inline)                   | 🟦 types defined; store wiring pending       |
| Policy evaluation, tickets, approvals on MCP calls                     | 🟦 design in `types.ts`; integration pending |
| Observability (metrics snapshot per 46.33)                             | 🟦 types defined; emit pending               |

Legend: ✅ **tested** (in `tests/mcp/`), 🟦 **designed** (types/contracts
exist, runtime not yet wired), ⬜ not started. Untested entries are marked
honestly here and in the [capability matrix](./capability-matrix.md); there is
no claim of completeness beyond what the tests prove.

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
```

## Quick start (protocol + reference server)

```ts
import { HttpConnection, McpReferenceServer } from "@rtq/mcp";

// Connect to a remote MCP server over HTTPS
const conn = new HttpConnection("https://mcp.example.com/mcp", {
  headers: { authorization: "Bearer <credential-ref>" }, // ref, never inline secret
});
await conn.connect();

const init = await conn.request("initialize", {
  protocolVersion: "2025-06-18",
  clientInfo: { name: "my-app", version: "1.0.0" },
  capabilities: {},
});
```

Or embed the reference server locally for tests and embedding:

```ts
import { InMemoryConnection, McpReferenceServer } from "@rtq/mcp";

const server = new McpReferenceServer({
  tools: [{ name: "echo", inputSchema: { type: "object" } }],
});
const conn = new InMemoryConnection(server);
await conn.connect();
const tools = await conn.request("tools/list", {});
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
- **Results as data.** Results are truncated or denied by size/depth,
  redacted for secret-shaped values, and annotated with _advisory_ flags for
  injection-like content. Flags never authorize anything.
- **Sandboxed local execution.** stdio servers can run inside the OS sandbox;
  when a sandbox is required and unavailable, the connection fails closed.

## Related docs

- [Security model](./security.md)
- [Configuration](./configuration.md)
- [Capability matrix](./capability-matrix.md)
- [Contract testing](./contract-testing.md)
