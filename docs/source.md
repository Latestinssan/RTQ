# RTQ provenance — design source and audit trail

RTQ is an original, standalone implementation. It was **not** copied,
renamed, or shipped from any other project — but it was _informed by a deep
audit_ of an existing federated MCP bridge application (hereafter "the
audited app"). This document records that trail exactly, so anyone can
verify the claims.

## What the audit was for

A security review of the audited app's authorization design produced a list
of security weaknesses. RTQ's own design was then written to **not repeat
them** and to provide a cleaner reference architecture. The audited app's
code is not part of RTQ's tree, was never copied, and none of its tests,
configuration, or implementation appears in RTQ.

## Weaknesses found in the audited app (design inputs, not features)

| Weakness                                     | How RTQ avoids it                                                                                                                 |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| PIN accepted as an authorization primitive   | RTQ has no PIN code path anywhere; device verification is always signed challenge-response (`packages/approval/src/challenge.ts`) |
| Ticket IDs sequential/predictable            | RTQ ticket IDs are v4 UUIDs (`packages/core/src/ticket-store.ts`)                                                                 |
| Non-recursive canonical JSON                 | RTQ's canonicalJSON is recursive and deterministic (`packages/crypto/src/canonical.ts`)                                           |
| Home-directory allowlist in sandbox defaults | RTQ sandbox specs have no implicit home-dir grants; default-deny (`docs/THREAT_MODEL.md`)                                         |
| Regex-only input validation                  | RTQ validates with JSON-schema (draft-7 style) plus input-hash binding (`packages/core/src/schema.ts`)                            |
| Approvals never expire                       | RTQ approvals are challenges with TTL, single use, purge (`packages/approval/src/challenge.ts`)                                   |
| Caller-supplied risk trusted                 | RTQ risk is authoritative; caller claims can only raise (`packages/risk/src/index.ts`)                                            |

These are documented as _design inputs_ — the weaknesses are real and public
knowledge from the audit; none of them is a feature RTQ ships.

## Design sources (beyond the audit)

RTQ's security-model layering (Command → Capability → Policy → Risk →
Clarification → Approval → Ticket → Execution → Sandbox → Audit) is derived
from standard industry references:

- NIST SP 800-207 (zero trust) — default-deny, explicit surface.
- OWASP Authorization Cheat Sheet — capability-based authorization,
  policy-per-request, separation of concerns.
- RFC 6749 style short-lived bearer semantics — adapted to single-use
  capability tickets (not OAuth; no flows beyond HMAC-signed tickets).

Links to these public references are in `SECURITY.md`.

## Technical audit of the audited app (how it was done)

The review was performed against the audited app's public repository. The
list below names the artifact kinds examined and the findings summarized
for RTQ's threat model. Exact files/lines of the _audited app_ are not
reproduced here (they are third-party content); instead, every RTQ source
file that was written in response is linked with its current line numbers:

| RTQ design decision          | RTQ source (this repo)                                                        |
| ---------------------------- | ----------------------------------------------------------------------------- |
| Default-deny policy          | `packages/policy/src/index.ts` (`defaultMode`, see `docs/THREAT_MODEL.md` T2) |
| Authoritative risk           | `packages/risk/src/index.ts:89-111`                                           |
| Single-use tickets           | `packages/core/src/ticket-store.ts:180-288`                                   |
| Challenge-response approvals | `packages/approval/src/challenge.ts:149-285`                                  |
| Fail-closed sandbox          | `packages/sandbox/src/index.ts:60-126`                                        |
| Env allowlist, no secrets    | `packages/sandbox/src/env.ts:51-140`                                          |
| Redacted audit               | `packages/audit/src/index.ts:99-113`                                          |

## What is NOT in RTQ (explicitly)

- No code, tests, configs, or assets from the audited app.
- No PIN-as-authz flow, no `approve=true` deep-link protocol.
- No sequential ticket IDs, no unsandboxed fallback.
- No unregistered implicit surface (no route that bypasses
  `registerCapability`).

## Verification

- `LICENSE` (Apache-2.0) and `NOTICE` declare origin.
- The twelve invariants (`tests/invariants/invariants.test.ts`) enforce the
  core claims above as code, and the audit trail is reproducible from the
  file:line links in `docs/THREAT_MODEL.md`.

If you believe any of the above is inaccurate, open an issue with the
specific claim.
