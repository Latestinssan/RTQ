# MCP Security Model

`@rtq/mcp` is an **integration/protocol layer, and it is explicitly NEVER an
authorization boundary.** Every byte that arrives over an MCP connection is
treated as **untrusted data** until RTQ's own components (policy, approval,
risk, sandbox, capability registry) rule on it.

## First principles

1. **Server input is data, not instructions.** Tool names, descriptions,
   prompt/result text, resource contents, and announced capabilities may all be
   hostile. RTQ routes them through schema validation, result normalization,
   and the authorization pipeline — it never executes or trusts them
   implicitly.
2. **The protocol layer fails closed.** Any construct it cannot safely
   interpret (unknown protocol version, `$ref`, `additionalProperties: true`,
   non-finite numbers, oversized or over-deep payloads) is denied or marked
   incomplete. Registration of an incomplete tool requires explicit policy
   approval; there is no "guess and proceed".
3. **Local processes are untrusted peers (spec 46.13).** A local stdio MCP
   server is not trusted because it is local. When a sandbox is configured and
   `sandboxRequired` is true, `connect()` refuses to run the process unless the
   platform reports **verified** OS isolation.
4. **Redaction is data protection, not authorization.** Secret-shaped values
   are scrubbed from result data delivered to callers, but the presence of a
   secret in a result never _denies_ or _approves_ anything; the advisory flags
   merely inform downstream policy evaluation.

## Threat model

| Threat                                                                    | Defense                                                                    |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Malformed/oversized JSON-RPC                                              | Byte-size limits, strict envelope, strict `2.0` version, no partial reads  |
| Tool schema smuggling (`$ref`, `additionalProperties: true`, unsafe keys) | Schema normalization marks incomplete → fail closed unless policy approves |
| Result with functions/BigInt/cycles                                       | `isJsonSerializable` gates; normalized results are canonical JSON only     |
| Result flooding (size/depth)                                              | Deny by default; optional truncation is explicit                           |
| Secret exfiltration inside results                                        | `redactValue` scrubs key/secret/bearer-shaped values                       |
| Prompt injection via tool output                                          | Advisory `injectionLike` flag surfaced for policy; never self-authorizing  |
| Hostile local server                                                      | Sandbox profile with verified enforcement; fail-closed required mode       |

## What this package does NOT do

- It does **not** decide whether a tool call is authorized.
- It does **not** evaluate risk, issue tickets, or grant approvals.
- It does **not** treat server-declared capabilities as capabilities RTQ
  trusts.
- It does **not** run remote code from MCP servers.

Authorization decisions belong to `@rtq/core` (capability registry),
`@rtq/policy`, `@rtq/risk`, `@rtq/approval`, and `@rtq/security`. This package
only delivers **normalized, shaped, sandboxed** inputs to that pipeline.

## Sandboxing rules

- `sandbox?: SandboxSpec` + `sandboxRequired: false` → sandbox when the
  platform can verify it; otherwise run unsandboxed and report honestly via
  `connection.enforcement`.
- `sandbox?: SandboxSpec` + `sandboxRequired: true` → **fail closed**: refuse
  to launch when the platform cannot provide verified OS isolation.
- `connection.enforcement` exposes the `EnforcementReport` (sandbox backend,
  verified status, notes) so callers can audit the actual enforcement state.

## Registry trust model (spec 46.5–46.8)

The registry in this package is RTQ's **bookkeeping layer, not a policy
layer**:

- Servers are recorded with a `McpTrustState` (`unknown`, `pending`,
  `approved`, `restricted`, `revoked`, `blocked`) that moves only through
  explicit, legal transitions. Everything else is ignored — never guessed.
- Server identity is keyed by a stable `serverId`; changed security-relevant
  metadata (transport, auth, sandbox, tenant, owner) recomputes `profileHash`,
  forces re-approval, and advances the registry `epoch` so previously bound
  authorizations are invalidated (46.7, 46.8).
- Tool discovery is lazy and untrusted: a discovered tool is `registered:
false` until RTQ's gateway explicitly registers it as executable after
  policy approval (46.3 — unknown tools default to denied).
- The registry holds **no credentials** and performs **no transport I/O**.
  Credentials live in the `McpCredentialVault`; transport happens on
  connection classes.

## Status

The security model above is implemented and unit-tested in `tests/mcp/`
(protocol, transports, schema hardening, result normalization, registry). All
tests run against **mock servers only** — no real API keys or live third-party
servers are ever used. See the [capability matrix](./capability-matrix.md) for
the per-capability breakdown of what is tested.

## Related docs

- [Configuration](./configuration.md)
- [Capability matrix](./capability-matrix.md)
- [Contract testing](./contract-testing.md)
- [README](./README.md)
