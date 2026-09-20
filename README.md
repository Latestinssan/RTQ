# RTQ — Risk-Adaptive Capability Security Runtime

RTQ is a standalone, dependency-free security library that turns "can this
agent/tool do this?" into a **provable pipeline**:

```
Command → Capability (registered) → Risk (authoritative) → Policy (default-deny)
       → Clarification (missing critical params) → Approval (human/device)
       → Authorization Ticket (signed, single-use, bound) → Execution (OS-sandboxed)
       → Audit (structured, redacted)
```

Each layer is a separate `@rtq/*` package with explicit types and tests — the
security model is never a blob inside one class.

> **Version:** `0.1.0` — **pre-1.0 / alpha**. The capability core, risk engine,
> policy engine, sandbox, CLI, and verification invariants are implemented and
> tested. Some features are designed but not yet wired (see the "Not started"
> / "Planned" rows in
> [docs/mcp/capability-matrix.md](docs/mcp/capability-matrix.md) and
> [docs/SECURITY_VERIFICATION_MATRIX.md](docs/SECURITY_VERIFICATION_MATRIX.md)).
> Do not assume production readiness.

## Why

AI agents, connectors, and MCP bridges routinely execute with ambient
authority: any prompt can reach any tool. RTQ inverts that. Every operation is
an explicitly **registered capability**; every authorization is a
**short-lived, single-use, cryptographically-signed ticket** bound to the exact
operation, risk, policy version, origin, and approval; every execution happens
inside an **OS-enforced sandbox** that fails closed.

RTQ was designed from a deep, file-by-file audit of a federated MCP bridge
application. It shares **none** of that application's code; several of that
application's weaknesses are explicitly designed out (see
[docs/source.md](docs/source.md)).

**RTQ and Aartiq.** RTQ and the audited application (named "Aartiq" on the
docs site) are **independent, unrelated projects**. RTQ shares none of
Aartiq's code, tests, or assets, and is a from-scratch, dependency-free
reimplementation of the same core thesis — *capability and authority are not
the same thing*. RTQ is designed to be **embeddable in any host** (an
Aartiq-style bridge, a connector, or a standalone agent), not just Aartiq.
Nothing in this repository claims that Aartiq currently uses, has migrated to,
or runs RTQ; the [Aartiq
integration](website/content/aartiq-integration.mdx) page describes how one
_would_ bring RTQ to such a host, it does not assert that integration exists
today.

## Packages

| Package              | Responsibility                                                                                        |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| `@rtq/crypto`        | canonical JSON, HMAC-SHA256, nonces, constant-time compare, redaction                                 |
| `@rtq/core`          | security model types, capability registry, ticket store, schema validation                            |
| `@rtq/risk`          | authoritative risk engine (caller claims can never downgrade)                                         |
| `@rtq/policy`        | declarative rules, default-deny, glob matching, risk overrides                                        |
| `@rtq/clarification` | structured questions for security-critical parameters                                                 |
| `@rtq/approval`      | strategies, challenge-response QR/mobile protocol, single-use challenge registry                      |
| `@rtq/sandbox`       | OS enforcement: macOS Seatbelt, Linux bubblewrap, Windows AppContainer+Job                            |
| `@rtq/audit`         | structured, redacted security events                                                                  |
| `@rtq/security`      | the full pipeline façade (`createRTQ`)                                                                |
| `@rtq/cli`           | actionable security tooling (`capabilities`, `policy check`, `sandbox test`, `verify`, `diagnostics`) |

## Quick start

```ts
import { createRTQ } from "@rtq/security";

const rtq = createRTQ({
  signingKey: process.env.RTQ_SIGNING_KEY!, // outside the repo, always
});

// 1. Explicitly register the executable surface.
rtq.registerCapability({
  name: "files.read",
  version: 1,
  description: "Read a file inside the workspace",
  inputSchema: {
    type: "object",
    properties: { path: { type: "string" } },
    required: ["path"],
    additionalProperties: false,
  },
  risk: { base: "low" },
  execute: async (ctx, input) => ({ ok: true, data: { input } }),
});

// 2. Declare policy. Missing rule ≠ allow: it is a denial.
rtq.registerPolicy({
  kind: "allow",
  capability: "files.read",
  reason: "workspace reads",
});

// 3. Authorize; consume the ticket exactly once.
const auth = await rtq.authorize({
  capability: "files.read",
  version: 1,
  input: { path: "/workspace/report.md" },
});
// auth.decision: 'allowed' | 'approval_required' | 'clarification_required' | 'denied'

if (auth.decision === "allowed") {
  const outcome = await rtq.execute(auth.ticketId);
  // outcome.ok, outcome.result ...
}
```

High-risk operations never auto-approve: they return
`approval_required` with a `challengeId`; the host renders a QR challenge,
a device that performed its own local authentication signs the exact
challenge, and `submitApproval` verifies and redeems it (single-use).

## Security posture (highlights)

- **Explicit surface.** Unregistered capabilities are denied — there is no
  implicit executable surface.
- **Default-deny policy.** A missing policy rule is a denial, not an allow.
- **Authoritative risk.** Risk is computed by RTQ from capability factors,
  origin and resource. A caller-supplied `claimedRisk` can only ever raise
  the baseline, never lower it.
- **Single-use tickets.** HMAC-SHA256 over a canonical body full of bindings
  (capability + version + input hash + actor + resource + risk + policy
  version + approval method + origin + challenge + expiry + nonce). Replay,
  tamper, expiry and version bumps are rejected with explicit codes. Tickets
  are invalidated when the capability version changes.
- **QR / mobile verification.** Challenge-response only; scanning a QR grants
  nothing. No `approve=true` deep links, no PINs as an authorization primitive.
- **Fail-closed sandbox.** If a backend cannot be constructed or verified, the
  execution is refused — there is no unsandboxed fallback. The only way to run
  unsandboxed is the explicit, host-supplied `useSandbox: false` escape hatch,
  which is reported as `sandboxed: false`.
- **Redacted audit.** Structured events cover every security transition;
  secret-shaped values are redacted before they reach a sink.

See [docs/security-overview.md](docs/security-overview.md),
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/SECURITY_VERIFICATION_MATRIX.md](docs/SECURITY_VERIFICATION_MATRIX.md).

## CLI

```sh
RTQ_SIGNING_KEY=... npx rtq capabilities --config settings/config.js
RTQ_SIGNING_KEY=... npx rtq policy check command.json --config settings/config.js --origin remote
npx rtq sandbox test
RTQ_SIGNING_KEY=... npx rtq verify signature --ticket ticket.json
npx rtq diagnostics
```

Every command is actionable: it prints what you need to decide and exits
nonzero when the answer is "not OK" (see `docs/cli.md`).

## Development

```sh
npm install
npm run typecheck     # whole-repo type check
npm run build         # package builds
npm test              # all suites
npm run test:unit     # unit tests only
npm run test:security # security pipeline + fs policy suites
npm run test:sandbox  # sandbox suites (real OS enforcement on macOS)
```

Test suites are labeled by category (`unit`, `contract`, `integration`,
`real OS enforcement`) — see [docs/testing.md](docs/testing.md). Real OS
enforcement tests always **skip with a reason** when the platform backend is
unavailable; they never fake a pass.

## Platform support

| OS      | Backend                                         | Real tests                                   |
| ------- | ----------------------------------------------- | -------------------------------------------- |
| macOS   | Seatbelt (`sandbox-exec`)                       | yes, gated on `/usr/bin/sandbox-exec`        |
| Linux   | bubblewrap (`bwrap`)                            | gated on install; argv unit tests always run |
| Windows | AppContainer + Job Object via PowerShell runner | runner unit tests; real on windows-latest    |

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). RTQ has no runtime
dependencies and is an original implementation — see
[docs/source.md](docs/source.md) for provenance and the audit trail behind
its design.
