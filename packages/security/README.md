# @rtq/security

**The RTQ security / invariant pipeline — device-bound approvals,
credential-class isolation, and the fail-closed execution guarantee that
§46.29 + §46.30 enforce.**

`@rtq/security` is the package that *ties RTQ together*: it constructs the
`RTQ` object from RTQ options (`createRTQ(options)` or `new RTQ(...)`), binds
the credential vault, risk, policy, sandbox, and approval sub-systems behind a
single fail-closed facade, and ships the danger-model tables + attack-surface
matrix the operator is expected to verify (§46.29 security-invariants, §46.30
security-matrix).

## What's inside

- `createRTQ(options)` / `class RTQ` — the RTQ composition root. It wires:
  - credential store (`McpCredentialStore`) + `McpCredentialVault` with
    **credential-class scoping** — a `credentialClassSignal("read")` returns
    `undefined`; only `admin`/`write` raise (§46.25 credentials).
  - risk: `McpRiskAdvisor` (baseline + raising contributions, §46.14/46.25)
  - policy: `McpPolicyEngine` (fail-closed, §46.16–46.32)
  - sandbox: `createSandbox` (§46.21–46.22)
  - approval: device-bound ticket parking (§46.19–46.20)
- `DeviceKeyStore` + credential isolation — a device/credential bound to a
  specific capability or server is **never** returned to an MCP server as
  plaintext; RTQ can only hand back a *pre-authorized credential ticket*
  bound to tool + argument hash (§46.27–46.28). A ticket is single-use,
  non-replayable, and argument-hash-bound (§46.19 #10, §46.20).
- Fail-closed **transport + tenant gates** (§46.28 #1–#6): unknown transport
  type, unknown tenant, or absent/empty allowlists → deny by default.
- The **danger models** for the MCP surface (transport, oversize,
  credential, server-text, network, approval/frau) as documented in
  `docs/mcp/security.md`; RTQ never guesses which one applied — it audits
  the classification that *was* applied (46.23–46.24) and denies anything
  unclassifiable.

## Security model

RTQ does not have a single "authentication" gate that MCP can bypass. The
pipeline denials happen at every stage and each one is **fail-closed**:

- **Unknown server/tool/operation** → denied (46.28 #1, #3, #5).
- **Unregistered or unapproved credential -> diverted / unknown-class** →
  denied (§46.28 #2 / §46.25 unclassified).
- **Un-normalizable schema / oversized result / deep nesting → denied**
  (§46.30 #13–#22 — `normalizeToolSchema` marks `incomplete`, the gateway
  treats anything `incomplete` as *denied*, never as "maybe ok").
- **Unknown risk advice → advisory-only raise; never authorizes** (§46.25
  #4 #6 #8 #11; `severity` is advisory and *can only go up*).
- **Approval required but not parked/approved** → parked ticket, no
  execution (§46.19 #11–#12; single-use ticket, §46.20).

## Example — deny an unregistered tool with a single line

```ts
import { createRTQ } from "@rtq/security";

const rtq = createRTQ({
  tenant: "acme",
  registry: rtqRegistry,
  allowTransport: new Set(["stdio"]), // fail-closed: untrusted transport denied
});
const result = await rtq.gateway.invoke("my-server", "delete_all", {});
// No policy rule allows delete_all and none granted a ticket → DENIED.
```

## Related

`@rtq/mcp` (the transport+gateway that §46.29/§46.30 validate against),
`@rtq/risk`, `@rtq/policy`, `@rtq/sandbox`, `@rtq/audit`.

## License

Apache-2.0
