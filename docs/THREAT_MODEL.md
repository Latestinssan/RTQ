# RTQ threat model

Applies to RTQ 0.1.x (pre-1.0). This document is an honest analysis: every
claim about the implementation cites an exact `file:line` in this repository,
and every claim about verification cites a test. Where a control is NOT
provided, that is stated explicitly.

## Assets

- **Authorization tickets** — the only way to execute a capability.
- **Approval challenges and device approvals** — the consent layer.
- **The audit stream** — evidence of what happened.
- **The executing process** — the thing that touches the outside world.
- **Signing material** — `RTQ_SIGNING_KEY`, device keys, secrets.

## Trust boundaries

```
[untrusted caller] ──command──▶ ┌────────────────────────────────┐
                                │ RTQ kernel (in-process)        │
[untrusted MCP/content] ◀──▶    │ registry · risk · policy ·      │
        (metadata, input,       │ approval · tickets · audit      │
         origin hints)          └──────────────┬─────────────────┘
                                               │ execute (authorized input, frozen)
                                               ▼
                              ┌──────────────────────────────────┐
                              │ OS sandbox (untrusted code runs  │
                              │ here, under denial-by-default)   │
                              └──────────────────────────────────┘
```

The caller, the command payload, and any content/agent it carries are
**untrusted**. The host that configures RTQ (capabilities, policy, approval
providers, keys) is the **trusted** entity.

## Threats and mitigations

### T1 — Executing an unregistered operation (implicit surface)

Capabilities are the only executable surface. Registry denies unknown names /
versions: `packages/core/src/capability-registry.ts:76` (`get`),
`:90` (`getRegisteredCapabilities`). Pipeline denies before
anything else: `packages/security/src/index.ts:285`.
**Verification:** `tests/security/pipeline.test.ts` — "denies unregistered
capabilities", "denies version mismatch".

### T2 — Missing/incomplete policy treated as allow

Policy defaults to deny when no rule matches:
`packages/policy/src/index.ts:148` (`defaultMode ?? "deny"`).
**Verification:** pipeline test "denies when no policy rule matches".

### T3 — Caller downgrades risk

Risk is computed authoritatively in
`packages/risk/src/index.ts:89-102`; `claimedRisk` may only raise the
baseline (`:96-101`). Origin hints are never trusted to lower risk
(`originEscalation`); `unknown` is never local.
**Verification:** pipeline test "caller-claimed low risk never downgrades",
"origin escalation".

### T4 — Input substitution after authorization

The exact input that will execute is frozen at issue time
(`packages/core/src/ticket-store.ts:167` — `deepFreeze`) and the hash is
signed into the ticket body (`:147`, `ticketBody()`), so a mutated input
cannot execute.
**Verification:** pipeline test "returns the frozen input, not caller
mutation, at execution".

### T5 — Ticket replay / tamper / expiry / version-change

Redeem is a synchronous, atomic status transition
(`packages/core/src/ticket-store.ts:180-288`): `redeemed` rejects re-use
(`:194-204`), tampering is detected via signature (`ticketBody` excludes
`status`/`signature` by design), expiry and capability-version changes are
checked, and `replaceCapability` invalidates live tickets.
**Verification:** pipeline tests "issues single-use tickets", "rejects
unknown tickets", "replacing a capability invalidates its outstanding
tickets"; `tests/sandbox/windows.test.ts` verifies the CLI's
`verify signature`.

### T6 — Approval substitution (approval for operation A used for B)

`submitApproval` verifies the device approval's challenge AND that the
redeemed challenge binds the same capability, version, input hash, nonce and
pending authorization before finalizing.
**Verification:** pipeline test "rejects approval substitution".

### T7 — QR/replay of approvals and challenges

The QR scan grants nothing; the challenge is a nonce bound to the exact
operation (`createChallenge`, `packages/approval/src/challenge.ts:149-172`),
device keys are resolved per-approval and never persisted by RTQ
(`verifyAndRedeem`, `:246-285`; `getDeviceKey` callback at `:248`, used at
`:275`), and challenges are single-use with expiry and replay rejection
(`:262`). Expired challenges are purged to keep the registry bounded
(`purgeExpired`, `:227`).
**Verification:** pipeline tests "rejects QR replay", "rejects approvals for
unknown challenges"; `tests/unit/approval.test.ts`.

### T8 — PIN / static deep-link approvals

**Designed out.** There is no `approve=true` deep-link and no PIN-as-authz
primitive anywhere in the repository; device verification always requires a
signature from a key that never leaves platform secure storage.
**Verification:** absence is auditable via the provenance audit
(`docs/source.md`) and the platform-support docs.

### T9 — Sandbox bypass / silent unsandboxed fallback

Sandbox construction fails closed
(`packages/sandbox/src/index.ts:60`, `:126`); unverified platforms get
`NO_ISOLATION` with `verified:false` and execution is refused. The only
unsandboxed path is the explicit `useSandbox: false` escape hatch (`:114`,
`:126`), which reports `sandboxed:false`.
**Verification:** `tests/sandbox/darwin.test.ts` (real Seatbelt: write
denial, network denial, env sanitization, escape-hatch reporting, fail-closed
on network allowlists) and `tests/sandbox/windows.test.ts` (runner never
claims isolation on failure).

### T10 — Secret leakage via environment or audit

Sandboxed processes get a constructed environment from an allowlist
(`packages/sandbox/src/env.ts:78`, `:51` secret-name pattern); auditor
redacts secret-shaped values before sinks
(`packages/audit/src/index.ts:99-113`).
**Verification:** Darwin real tests "environment allowlist", "env
sanitization"; pipeline audit test "records the full authorization lifecycle
without secrets".

### T11 — Path traversal / symlink escape in filesystem policy

Paths are canonicalized (`~`, realpath, symlinks) and matched with
separator-aware boundaries
(`packages/sandbox/src/path.ts:28-54` and `isPathAllowed`).
**Verification:** `tests/fs/path.test.ts` (traversal, symlink escape,
boundary, op separation).

### T12 — Audit forgery / unlabelled decisions

Every security transition has a structured, name-keyed event
(`packages/audit/src/types.ts` — `AUDIT_EVENTS`); TICKET_REPLAYED etc. are
emitted by the store and surface in the pipeline.
**Verification:** pipeline audit tests.

## Explicitly out of scope (honest limitations)

- **The host is trusted.** RTQ runs in the host process; a compromised host
  can re-register capabilities or swap the signing key. Sandboxing is
  process-level, not machine-level.
- **bwrap is not a root boundary** (`packages/sandbox/src/linux.ts` notes;
  CI runs unprivileged).
- **macOS Seatbelt**: `sandbox-exec` is deprecated by Apple; Mach IPC remains
  default-allowed (`packages/sandbox/src/darwin.ts` report notes).
- **Windows AppContainer**: target stdout/stderr are not captured by the
  runner (`windowsReport` notes); integrity level is AppContainer (not
  medium/low full-token).
- **Local authentication on the verifying device** is the device's
  responsibility; RTQ verifies the signature, not the human behind it.
- **Side channels (timing in HMAC)** are mitigated with constant-time
  comparison at the primitive level (`@rtq/crypto` `timingSafeEqualHex`);
  full host-level side-channel resistance is out of scope.

## Residual risks

1. A malicious host defeats any in-process control (trust boundary).
2. Social engineering of the approving human — RTQ shows a precise summary
   (`describeCommand`), but a human can still approve the wrong thing.
3. Vulnerabilities in the OS sandbox backends themselves (Seatbelt/bwrap/
   AppContainer) are outside RTQ's code.

## Verification maturity

See `docs/SECURITY_VERIFICATION_MATRIX.md` for the per-claim status of every
claim in this document, and `docs/source.md` for the audit trail behind the
design.
