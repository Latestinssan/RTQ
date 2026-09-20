# Contract Testing (`tests/mcp/`)

All MCP tests are **hermetic**: they run against mock servers inside the test
process with zero live credentials.

## Test layout

```
tests/mcp/
  unit/
    protocol.test.ts            Wire protocol: parse, build, negotiate
    transports-in-memory.test.ts In-memory transport + reference-server contract
    transports-http.test.ts     HTTP transport against a local mock endpoint
    transports-stdio.test.ts    stdio transport against a fixture process
    server.test.ts              Reference server behavior
    schemas.test.ts             Schema normalization/hardening
    results.test.ts             Result normalization/redaction/flags
    registry.test.ts            Server/tool trust records, transitions, epoch
  helpers/
    stdio-fixture.mjs           Minimal stdio MCP server (test double)
```

## What the contract tests prove

- **Wire fidelity.** Requests/notifications/responses built by the layer can be
  parsed back through the same defensive parser; server replies (JSON and SSE)
  are parsed with the same size/strictness rules as production traffic.
- **Adversarial inputs.** `parseJsonRpcMessage` is exercised with malformed
  JSON, unknown envelope fields, wrong versions, oversized messages, and
  response/request shape violations.
- **Schema hardening.** Hostile schemas (`$ref`, `additionalProperties: true`,
  `__proto__` own keys from parsed JSON, tuple items, non-finite numbers) are
  flagged `incomplete` so tools fail closed on registration.
- **Result pipeline.** Secret-shaped values are detected on the raw result and
  redacted before delivery; injection-like content is flagged but never denies.
- **Transport semantics.** In-memory and HTTP timeouts, abort signals,
  malformed-response handling, and error propagation are all covered.

## Running

```sh
npm run test:mcp            # MCP suite only (vitest run tests/mcp)
npm test                    # full monorepo suite
npx vitest run tests/mcp/unit/transports-http.test.ts  # single file
```

## CI

The GitHub Actions workflow (see `.github/workflows/`) runs these tests with no
secrets configured. No test in this repository contacts a real MCP server, and
no real API keys exist in the repository or CI environment.

## Adding a contract test

1. Prefer the in-memory `McpReferenceServer` when testing protocol semantics.
2. Use the local mock HTTP server / stdio fixture for transport framing.
3. Never add a test that requires network access to a third-party service or a
   live credential; such tests would be skipped by the honest-status rule.
4. Mark capability-matrix status accurately — ✅ only when the new test proves
   the behavior.
