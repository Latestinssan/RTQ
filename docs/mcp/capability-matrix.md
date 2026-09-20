# Capability Matrix — `@rtq/mcp`

> **Legend:** ✅ **tested** — covered by automated tests in `tests/mcp/` (all
> tests run against mock servers; no live API keys are ever used). 🟦 **designed**
> — type/contract exists, runtime not yet wired. ⬜ not started.
> Honesty rule: an entry is marked ✅ only when a test proves it.

## Protocol

| Capability                                                | Status | Notes                              |
| --------------------------------------------------------- | ------ | ---------------------------------- |
| JSON-RPC 2.0 parse (request/notification/response/error)  | ✅     | 26 tests in `protocol.test.ts`     |
| Strict envelope (unknown fields rejected)                 | ✅     | verifiable in tests                |
| Byte-size limits, parse errors                            | ✅     | oversized message denied pre-parse |
| Message builders (makeRequest/Notification/Success/Error) | ✅     | round-trip tested                  |
| Version negotiation (highest common; oldest fallback)     | ✅     | `negotiateProtocolVersion`         |
| `isKnownProtocolVersion` strict check                     | ✅     | garbage rejected                   |

## Transports

| Capability                               | Status | Notes                                             |
| ---------------------------------------- | ------ | ------------------------------------------------- |
| In-memory transport                      | ✅     | request/notify/timeout/abort/error tests          |
| stdio transport (framing, IDs, timeouts) | ✅     | against `stdio-fixture.mjs` mock                  |
| stdio sandbox fail-closed path           | 🟦     | logic present; platform gates need platform tests |
| HTTP transport (JSON + SSE)              | ✅     | against local mock HTTP server                    |
| HTTP error responses surfaced            | ✅     | JSON-RPC error objects propagate                  |
| Custom headers (credential-ref contract) | ✅     | authorization header behavior verified            |
| AbortSignal support                      | ✅     | external cancellation honored                     |

## Reference server (embedding & contract tests)

| Capability                               | Status | Notes                               |
| ---------------------------------------- | ------ | ----------------------------------- |
| `initialize` handshake + negotiation     | ✅     | version + serverInfo + capabilities |
| `ping`                                   | ✅     |                                     |
| `tools/list` / `tools/call`              | ✅     | schema-driven args through wire     |
| `resources/list` / `resources/read`      | ✅     |                                     |
| `prompts/list` / `prompts/get`           | ✅     |                                     |
| Notifications handled (side-effect free) | ✅     |                                     |
| Unknown method → `-32601`                | ✅     |                                     |
| Internal handler failure → `-32603`      | ✅     |                                     |
| Dynamic tool replacement (`setTools`)    | ✅     |                                     |

## Schema normalization (hardening)

| Capability                                            | Status | Notes                           |
| ----------------------------------------------------- | ------ | ------------------------------- |
| Default `additionalProperties: false`                 | ✅     |                                 |
| Caps on string/array lengths                          | ✅     | server caps clamped to RTQ caps |
| `$ref` / `allOf` / `if-then-else` / `not` rejected    | ✅     | incomplete → fail closed        |
| Complex `anyOf` → incomplete                          | ✅     | simple unions mapped to `oneOf` |
| Unsafe keys (`__proto__`, `constructor`, `prototype`) | ✅     | JSON-owned keys rejected        |
| Non-finite numbers rejected                           | ✅     |                                 |
| `nullable` → hardened `oneOf`                         | ✅     | base variant keeps constraints  |
| Schema depth limits                                   | ✅     |                                 |
| `computeToolSchemaHash` stable                        | ✅     |                                 |
| Argument validation rejects unknown fields            | ✅     | `validateToolArguments`         |

## Result normalization

| Capability                                                 | Status | Notes                          |
| ---------------------------------------------------------- | ------ | ------------------------------ |
| JSON-serializability gate                                  | ✅     | functions/BigInt/cycles denied |
| Size limit deny / explicit truncate                        | ✅     |                                |
| Depth limit deny                                           | ✅     |                                |
| Secret-shaped value detection (advisory flag)              | ✅     | on raw result                  |
| Secret redaction before delivery                           | ✅     |                                |
| Prompt-injection-like flag (advisory)                      | ✅     | never self-authorizing         |
| Provenance (server, tool, invocation, ticket, schema hash) | ✅     | missing invocationId filled    |

## Registry (server/tool trust records)

| Capability                                                    | Status | Notes                            |
| ------------------------------------------------------------- | ------ | -------------------------------- |
| `registerServer` (record + profile hash, default `pending`)   | ✅     | 19 tests in `registry.test.ts`   |
| `updateServer` (idempotent when profile unchanged)            | ✅     | keeps tool state on no-op re-reg |
| Profile change → `needsReapproval` + epoch bump               | ✅     | fail-closed invalidation         |
| Legal trust transitions only (`pending/approved/.../blocked`) | ✅     | illegal transitions rejected     |
| Terminal `blocked` state                                      | ✅     | no exit transition               |
| Same-state transition is a no-op                              | ✅     | no spurious epoch bump           |
| `registerTool` non-executable by default (`registered:false`) | ✅     | unknown tools default to denied  |
| Idempotent tool re-register (same name + schema hash)         | ✅     | no epoch bump                    |
| Schema change → `metaRevision` bump + invalidation            | ✅     | `tool_updated` event             |
| Incomplete (unsupported schema) tools marked                  | ✅     | `needsReevaluation` set          |
| `registerToolAsExecutable` (gateway-only, after approval)     | ✅     | only path to `registered:true`   |
| `revokeServer` (returns tool count, sets `revoked`)           | ✅     |                                  |
| `onChange` post-commit events                                 | ✅     | epoch monotonic                  |
| `serverProfileHash` stable / changes on security fields       | ✅     |                                  |

## Planned (not started)

- Wiring policy/risk/approval evaluation into tool-call dispatch.
- Observability metrics snapshot (MCP 46.33).
- Credential store wiring (currently placeholder refs only).
- Platform-gated sandbox enforcement integration tests (Windows/darwin/linux
  backends beyond unit-level checks).
