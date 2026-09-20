# RTQ security verification matrix

Every security claim that RTQ makes is listed here with its verification
status. Statuses are **honest**: `verified` means a test proves it on this
repository, `verified (gated)` means the test proves it only when the listed
OS backend is present (otherwise it skips with a reason), and `construction
only` means the listed test checks the construction layer (argv/profile/env)
but does not claim OS-level enforcement by itself.

Legend:

- `unit` — pure logic test, runs everywhere.
- `contract` — cross-component test (ticket + approval + pipeline), runs everywhere.
- `integration` — full pipeline tests, runs everywhere.
- `real OS enforcement` — runs a real OS sandbox; **gated on backend presence**.

## The twelve automated invariants

Encoded in `tests/invariants/invariants.test.ts` — 12 standalone assertions
that run in CI on every platform (the sandbox construction checks build the
enforcement layer that the real backends execute).

| #   | Invariant                                                          | Status                                         | Where                                                                                                 |
| --- | ------------------------------------------------------------------ | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| I1  | Unregistered capability denied (no implicit surface)               | verified (unit/contract)                       | `tests/invariants/invariants.test.ts`, `tests/security/pipeline.test.ts`                              |
| I2  | Version mismatch denied                                            | verified (contract)                            | `tests/invariants/invariants.test.ts`, `tests/security/pipeline.test.ts`                              |
| I3  | Missing policy rule ≠ allow (default deny)                         | verified (unit/contract)                       | `tests/invariants/invariants.test.ts`, `tests/security/pipeline.test.ts`, `tests/unit/policy.test.ts` |
| I4  | Caller-claimed low risk never downgrades                           | verified (integration)                         | `tests/invariants/invariants.test.ts`, `tests/security/pipeline.test.ts`                              |
| I5  | Origin is a hint; `unknown` is never local and escalates           | verified (integration)                         | `tests/invariants/invariants.test.ts`, `tests/security/pipeline.test.ts`, `tests/unit/risk.test.ts`   |
| I6  | High/critical risk never automatically approved                    | verified (integration)                         | `tests/invariants/invariants.test.ts`, `tests/security/pipeline.test.ts`                              |
| I7  | Sandbox network default deny; unenforceable allowlist refused      | construction only (bwrap) + real on Linux      | `tests/invariants/invariants.test.ts`, `tests/sandbox/linux.test.ts`                                  |
| I8  | Sandboxed process never inherits ambient secrets via env           | construction only (env builder); real on macOS | `tests/invariants/invariants.test.ts`, `tests/sandbox/darwin.test.ts`                                 |
| I9  | Tickets single-use; replay denied                                  | verified (integration)                         | `tests/invariants/invariants.test.ts`, `tests/security/pipeline.test.ts`                              |
| I10 | Ticket tamper/replay resistant at the cryptogram level             | verified (unit)                                | `tests/unit/ticket-store.test.ts`, `tests/security/pipeline.test.ts`                                  |
| I11 | Replacing a capability invalidates outstanding tickets             | verified (integration)                         | `tests/invariants/invariants.test.ts`, `tests/security/pipeline.test.ts`                              |
| I12 | Approval substitution rejected (approval for A cannot authorize B) | verified (integration)                         | `tests/invariants/invariants.test.ts`, `tests/security/pipeline.test.ts`                              |

## Claim-by-claim status

### Capability surface & registry

| Claim                                                              | Status   | Evidence                                                                  |
| ------------------------------------------------------------------ | -------- | ------------------------------------------------------------------------- |
| Capabilities must be explicitly registered before they can execute | verified | `tests/invariants/invariants.test.ts` (I1); `tests/unit/registry.test.ts` |
| Capability versions are enforced at authorization                  | verified | `tests/security/pipeline.test.ts` ("denies version mismatch")             |
| Replacing a capability invalidates its outstanding tickets         | verified | `tests/security/pipeline.test.ts` ("replacing a capability invalidates…") |

### Policy

| Claim                                                                    | Status   | Evidence                                                       |
| ------------------------------------------------------------------------ | -------- | -------------------------------------------------------------- |
| Policy default-deny (`defaultMode: "deny"`)                              | verified | `tests/unit/policy.test.ts`; invariant I3                      |
| Deny beats allow                                                         | verified | `tests/unit/policy.test.ts`                                    |
| Glob rules (`files.**` → `^files\..*$`), wildcards                       | verified | `tests/unit/policy.test.ts`                                    |
| `requireClarification` / `requireApproval` / `requireVerification` rules | verified | `tests/unit/policy.test.ts`, `tests/security/pipeline.test.ts` |
| Risk overrides only raise, never lower                                   | verified | `tests/unit/policy.test.ts`, `tests/security/pipeline.test.ts` |

### Risk engine

| Claim                                       | Status   | Evidence                                                                       |
| ------------------------------------------- | -------- | ------------------------------------------------------------------------------ |
| Risk computed by RTQ is authoritative       | verified | `tests/unit/risk.test.ts`; invariant I4                                        |
| `claimedRisk` can only raise the baseline   | verified | `tests/security/pipeline.test.ts` ("caller-claimed low risk never downgrades") |
| Origin escalation: remote/mobile/unknown +1 | verified | `tests/unit/risk.test.ts`; pipeline "origin escalation"                        |
| `unknown` origin never treated as local     | verified | `tests/invariants/invariants.test.ts` (I5)                                     |

### Clarification

| Claim                                                | Status   | Evidence                                                                                                        |
| ---------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------- |
| Missing security-critical params block authorization | verified | `tests/security/pipeline.test.ts` ("clarification required for ambiguous…"); `tests/unit/clarification.test.ts` |

### Approval

| Claim                                                                     | Status                      | Evidence                                                                                                   |
| ------------------------------------------------------------------------- | --------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Defaults: LOW=auto, MEDIUM=user_confirmation, HIGH=qr, CRITICAL=biometric | verified (code)             | `packages/security/src/index.ts` (`riskDefaultStrategy`); invariant I6                                     |
| Policy overrides approval strategy                                        | verified                    | `tests/unit/policy.test.ts`, pipeline "custom approval providers"                                          |
| QR challenge-response; scanning grants nothing                            | verified                    | `tests/unit/approval.test.ts`, pipeline "completes the QR/device-verification flow"                        |
| No `approve=true` deep link; no PIN-as-authz primitive                    | verified (absence + design) | `tests/unit/approval.test.ts` ("never carries a PIN or a pre-baked approval"); audit in `docs/source.md`   |
| Device approval signed (HMAC-SHA256) and verified in constant time        | verified                    | `tests/unit/approval.test.ts` ("signs and verifies device approvals in constant time")                     |
| Challenges single-use and short-lived; expired ones purged                | verified                    | `tests/unit/approval.test.ts` ("rejects expired challenges", registry purge); pipeline "rejects QR replay" |
| Approval substitution prevented                                           | verified                    | `tests/security/pipeline.test.ts` ("rejects approval substitution"); invariant I12                         |

### Tickets

| Claim                                                                                                                                   | Status          | Evidence                                                             |
| --------------------------------------------------------------------------------------------------------------------------------------- | --------------- | -------------------------------------------------------------------- |
| HMAC-SHA256 over canonical body; `status`/`signature` excluded                                                                          | verified (unit) | `tests/unit/ticket-store.test.ts`                                    |
| Single-use; synchronous atomic redemption                                                                                               | verified        | `tests/unit/ticket-store.test.ts`; invariant I9                      |
| Replay, expiry, tamper, unknown-ticket rejected with codes                                                                              | verified        | `tests/unit/ticket-store.test.ts`, `tests/security/pipeline.test.ts` |
| Invalidated on capability version change                                                                                                | verified        | invariant I11, pipeline "replacing a capability invalidates…"        |
| Bound to capability+version+input hash+actor+resource+risk+policy version+approval method+origin+challenge+expiry+nonce (body bindings) | verified (unit) | `tests/unit/ticket-store.test.ts`                                    |
| MCP ticket bindings (server, tool, schema hash, tenant) enforced at redemption                                                          | verified        | MCP suites (`tests/mcp/**` — see that package's CI)                  |

### Sandbox — per-layer enforcement reporting

| Claim                                                                            | Status                                           | Evidence                                                                                          |
| -------------------------------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| Platform backend constructed; unsupported platform fails closed                  | verified (unit)                                  | `tests/sandbox/linux.test.ts`, `tests/sandbox/windows.test.ts`                                    |
| macOS Seatbelt: write blocked to read-only dirs                                  | **verified (real OS enforcement)**               | `tests/sandbox/darwin.test.ts` — runs `sandbox-exec`                                              |
| macOS Seatbelt: network deny (none) blocks egress                                | **verified (real OS enforcement)**               | `tests/sandbox/darwin.test.ts`                                                                    |
| macOS Seatbelt: environment sanitized for the child                              | **verified (real OS enforcement)**               | `tests/sandbox/darwin.test.ts`                                                                    |
| Escape hatch `useSandbox:false` reports `sandboxed:false`                        | **verified (real OS enforcement)**               | `tests/sandbox/darwin.test.ts` ("reports sandboxed:false when the explicit escape hatch is used") |
| Fail-closed: unsupported network allowlist refused, never silently downgraded    | **verified (real OS enforcement)**               | `tests/sandbox/darwin.test.ts`                                                                    |
| Linux bwrap: argv unshares net/user/pid, ro/rw binds, private /dev,/tmp          | construction only locally; real on ubuntu-latest | `tests/sandbox/linux.test.ts`                                                                     |
| Windows AppContainer+Job runner reports `sandboxed`/`jobAssigned`/`appContainer` | verified (unit) on runner output parser          | `tests/sandbox/windows.test.ts`                                                                   |

### Filesystem policy layer (`@rtq/sandbox` path module)

| Claim                                                       | Status   | Evidence                |
| ----------------------------------------------------------- | -------- | ----------------------- |
| Paths canonicalized (realpath, `~`, symlink resolution)     | verified | `tests/fs/path.test.ts` |
| Boundary separator-aware (`/workspace` ≠ `/workspace-evil`) | verified | `tests/fs/path.test.ts` |
| Read/write/delete kept separate                             | verified | `tests/fs/path.test.ts` |
| Empty allowlist = default deny                              | verified | `tests/fs/path.test.ts` |

### Audit

| Claim                                           | Status   | Evidence                                                                                   |
| ----------------------------------------------- | -------- | ------------------------------------------------------------------------------------------ |
| Structured events for every security transition | verified | `tests/security/pipeline.test.ts` ("records the full authorization lifecycle")             |
| Secret-shaped values redacted before sinks      | verified | `tests/security/pipeline.test.ts`; `tests/unit/audit.test.ts`, `tests/unit/crypto.test.ts` |
| Memory sink snapshot; JSONL file sink           | verified | `tests/unit/audit.test.ts`                                                                 |

### CLI

| Claim                                                                                                               | Status   | Evidence                               |
| ------------------------------------------------------------------------------------------------------------------- | -------- | -------------------------------------- |
| `capabilities` / `policy check --origin` / `verify signature` / `diagnostics` exit codes distinguish OK from not-OK | verified | `tests/cli/cli.test.ts` (exit 0/2/3/4) |
| `verify signature` rejects a tampered ticket                                                                        | verified | `tests/cli/cli.test.ts`                |

## Verification provenance

This matrix is filled from the local test run at the time of writing. The
exact tree SHA and CI workflow run IDs are recorded after the first CI run
(see `SECURITY.md` → Verification provenance). Nothing in this matrix is
fabricated; every row names a real test file in this repository.

Run locally:

```sh
npm run test:unit        # unit suites
npm run test:security    # pipeline + audit
npm run test:fs          # filesystem policy layer
npm run test:sandbox     # sandbox (real Seatbelt on macOS)
npm run test:cli         # CLI exit-code contracts
npx vitest run tests/invariants   # the twelve invariants
```
