# Configuration

This page describes how to construct and configure MCP server connections,
limits, the reference/embedded server, and the registry.

## Connections

All connections implement the `McpConnection` interface:

```ts
interface McpConnection {
  readonly kind: "in-memory" | "stdio" | "http";
  connect(): Promise<void>;
  request(
    method: string,
    params: unknown,
    opts: {
      timeoutMs?: number;
      signal?: AbortSignal;
    },
  ): Promise<unknown>;
  notify(method: string, params: unknown): Promise<void>;
  close(): Promise<void>;
  readonly enforcement?: EnforcementReport;
  readonly protocolLimits: ProtocolLimits;
}
```

### In-memory (embedded reference server)

```ts
import { InMemoryConnection, McpReferenceServer } from "@rtq/mcp";

const server = new McpReferenceServer({
  name: "my-server",
  tools: [{ name: "echo", inputSchema: { type: "object" } }],
});
const conn = new InMemoryConnection(server);
await conn.connect();
```

### stdio (local process)

```ts
import { StdioConnection } from "@rtq/mcp";

const conn = new StdioConnection("node", ["server/entry.mjs"], {
  cwd: "/opt/my-server",
  env: { RTQ_ENV: "prod" },
  // Optional: require verified OS isolation (fail closed). The spec
  // describes the OS boundary; `sandboxRequired: true` refuses to launch
  // unless the platform reports verified enforcement.
  sandbox: {
    filesystem: { read: ["/etc/passwd"], write: ["/tmp/out"] },
    network: { allow: ["api.example.com"] },
  },
  sandboxRequired: true,
});
await conn.connect();
```

### HTTP (remote server)

```ts
import { HttpConnection } from "@rtq/mcp";

const conn = new HttpConnection("https://mcp.example.com/mcp", {
  headers: { authorization: "Bearer credential-ref" }, // a REF, never an inline secret
});
await conn.connect();
```

HTTPS is the expected deployment; plain `http://` endpoints are acceptable in
tests against local mock servers but should be rejected in production policy.

## Protocol limits

Every connection enforces `ProtocolLimits` as messages pass through the
defensive parser. Defaults (from `DEFAULT_PROTOCOL_LIMITS`):

| Limit             | Default                          |
| ----------------- | -------------------------------- |
| `maxMessageBytes` | 1 MiB                            |
| `strictEnvelope`  | `true` (unknown fields rejected) |

```ts
const conn = new HttpConnection(url, {
  protocolLimits: { maxMessageBytes: 512 * 1024, strictEnvelope: true },
});
```

## Reference server options

```ts
new McpReferenceServer({
  name?: string;                          // default "rtq-reference"
  version?: string;                       // default "0.0.0"
  supportedProtocolVersions?: string[];   // default [2024-11-05, 2025-06-18]
  serverInfo?: Record<string, unknown>;
  tools?: ReferenceTool[];
  resources?: ReferenceResource[];
  prompts?: ReferencePrompt[];
  setTools?: (setter: (tools: ReferenceTool[]) => void) => void; // test hook
})
```

Tools are declared with `name`, `description`, `inputSchema`, and an optional
`handler`. The reference server serializes handler output through a results
pipeline on `tools/call`, so contract tests exercise real wire behavior.

## Result normalization options

```ts
normalizeMcpResult(raw, {
  maxBytes?: number;   // default 1 MiB
  maxDepth?: number;   // default 12
  truncate?: boolean;  // deny by default; truncation must be explicit
  strictJson?: boolean;
}, provenance);
```

## Schema normalization limits

`normalizeToolSchema` defaults: `maxSchemaDepth` 24, `maxStringLength` 64 KiB,
`maxItems` 1000, `maxProperties` 256. Limits can be overridden per call or via
`buildSchemaNormalizationLimits(limits, allowIncomplete)`.

## Registry configuration (`McpRegistry`)

The registry is the RTQ-trusted record of servers, their trust state, and
discovered tools. It performs no network I/O and holds no credentials.

```ts
import { McpRegistry } from "@rtq/mcp";

const registry = new McpRegistry({
  // Optional operational limits (see McpLimits in types.ts).
  connectTimeoutMs: 10_000,
  requestTimeoutMs: 30_000,
});

// Observe post-commit events (e.g. to invalidate RTQ tickets on change).
registry.onChange = (event) => {
  // event.kind: server_registered | server_updated | server_trust_changed
  //             | tool_registered | tool_updated
  // event.epoch is the post-commit registry epoch.
};

const server = registry.registerServer({
  serverId: "srv-github",
  name: "GitHub Tools",
  version: "1.0.0",
  transport: { kind: "http", url: "https://mcp.example.com/mcp" },
  auth: { method: "bearer", credentialRef: "ref://vault/github" },
  defaultSeverity: "high",
  initialTrust: "pending", // registrations default to pending (denied)
});

// Discovered tools are untrusted and non-executable until the gateway
// registers them as executable after policy approval.
const tool = registry.registerTool(server.serverId, {
  name: "read_file",
  description: "Read a file (server-declared, untrusted)",
  rawSchema: { type: "object", properties: { path: { type: "string" } } },
  normalizedSchema: {
    type: "object",
    properties: { path: { type: "string" } },
  },
  schemaHash: "...", // computed via computeToolSchemaHash
  protocolVersion: "2025-06-18",
  incomplete: false,
});

registry.registerToolAsExecutable(server.serverId, "read_file");
```

For the interaction between `RawService`s, `registerTool` untrusted content,
failure modes, and the fail-closed rules, see the
[security model](./security.md). Matching inbound tool calls to records is
done by `serverId` + tool `capabilityName` — never by server-declared text.
