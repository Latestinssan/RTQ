# RTQ security overview

RTQ (`Risk-Adaptive Capability` runtime) is a library that answers one
question: **"Can this agent/tool do this, safely?"** — and then proves the
answer with a cryptographic ticket and an OS-enforced sandbox.

## The pipeline

```
Command            structured { capability, version, input, origin?, metadata? }
  │
  ▼
Capability         explicit registry; unknown name/version → DENY
  │
  ▼
Risk               authoritative, RTQ-computed (caller claims can only raise)
  │
  ▼
Policy             declarative rules; missing rule ≠ allow (default deny)
  │
  ▼
Clarification      security-critical params missing → questions, no authz
  │
  ▼
Approval           automatic / user_confirmation / device_verification(QR) /
                   biometric; single-use short-lived challenges
  │
  ▼
Ticket             HMAC-SHA256, bound to the operation, single-use
  │
  ▼
Execution          OS sandbox (Seatbelt / bubblewrap / AppContainer+Job)
  │
  ▼
Audit              structured, redacted events for every transition
```

## Core principles

1. **Explicit surface.** Only `registerCapability` results can run. There is
   no "all tools" escape hatch. (Invariant I1/I2.)
2. **Default deny.** Missing policy is a denial; deny beats allow.
   (Invariant I3.)
3. **Authoritative risk.** Risk is computed by RTQ from the capability
   declaration, origin, and resource. A caller claiming "this is low risk"
   cannot downgrade anything — at best it is ignored. (Invariant I4.)
4. **Origin is a hint.** `remote`/`mobile`/`unknown` escalate; `unknown` is
   never treated as local. (Invariant I5.)
5. **Approval escalates with risk.** HIGH and CRITICAL are never automatic.
   (Invariant I6.)
6. **Single-use tickets.** One execution per ticket, atomically. Replay and
   tampering are rejected. Version changes invalidate tickets.
   (Invariants I9–I11.)
7. **Fail-closed sandbox.** No sandbox → no execution. The only unsandboxed
   path is an explicit, reported `useSandbox: false`. (Invariants I7/I8.)
8. **No ambient secrets.** The sandboxed child gets an explicitly constructed
   environment, and audit redacts secret-shaped values.

## Where each principle lives

| Principle                  | Package              | Key file                                                                  |
| -------------------------- | -------------------- | ------------------------------------------------------------------------- |
| Model + registry + tickets | `@rtq/core`          | `packages/core/src/capability-registry.ts`, `ticket-store.ts`, `types.ts` |
| Risk                       | `@rtq/risk`          | `packages/risk/src/index.ts`                                              |
| Policy                     | `@rtq/policy`        | `packages/policy/src/index.ts`                                            |
| Clarification              | `@rtq/clarification` | `packages/clarification/src/index.ts`                                     |
| Approval                   | `@rtq/approval`      | `packages/approval/src/challenge.ts`                                      |
| Sandbox                    | `@rtq/sandbox`       | `packages/sandbox/src/{darwin,linux,windows,env,path}.ts`                 |
| Audit                      | `@rtq/audit`         | `packages/audit/src/index.ts`                                             |
| Facade                     | `@rtq/security`      | `packages/security/src/index.ts` (`createRTQ`)                            |
| Crypto primitives          | `@rtq/crypto`        | `packages/crypto/src/*`                                                   |
| Tooling                    | `@rtq/cli`           | `packages/cli/src/index.ts`                                               |

## Failure modes RTQ makes impossible

- Running an unregistered tool ("prompt → shell" bypass).
- "Policy wasn't reviewed yet, so let it through."
- A caller downgrading its own risk to skip a human check.
- Replaying a captured authorization.
- Swapping an approval from one operation onto another.
- An OS sandbox silently not applying (every execution reports what was
  applied).
- Secrets leaking into the child process or the log stream.

## Extended reading

- [Threat model](THREAT_MODEL.md)
- [Security verification matrix](SECURITY_VERIFICATION_MATRIX.md)
- [Provenance / audit trail](source.md)
- [Testing strategy](testing.md)
- [Platform support](platform-support.md)
