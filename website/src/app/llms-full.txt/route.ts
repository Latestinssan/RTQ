import { NextResponse } from "next/server";
import { APP_INFO } from "@/lib/version";

export async function GET() {
  const content = `# ${APP_INFO.fullName}

> ${APP_INFO.description}

## Overview

RTQ is a dependency-free, risk-adaptive capability-security runtime. Every operation is an explicitly registered capability; every authorization is a short-lived, single-use, cryptographically-signed ticket.

### Core Pipeline

Command → Capability (registered) → Risk (authoritative) → Policy (default-deny)
  → Clarification → Approval (human/device) → Ticket (signed, single-use)
  → Execution (OS-sandboxed) → Audit (redacted)

### Packages

- @rtq/core — Security-model types, registry, ticket store
- @rtq/risk — Authoritative risk engine
- @rtq/policy — Default-deny declarative rules
- @rtq/clarification — Structured questions for missing params
- @rtq/approval — Strategies + QR/mobile challenge-response
- @rtq/sandbox — macOS Seatbelt, Linux bubblewrap, Windows AppContainer
- @rtq/audit — Structured, redacted events
- @rtq/security — Pipeline facade (createRTQ)
- @rtq/crypto — Canonical JSON, HMAC-SHA256, constant-time compare
- @rtq/cli — Actionable operator tooling

## Security Model

### Core Principles

1. Explicit Surface: Only registered capabilities can run. Everything else is denied.
2. Default Deny: A missing rule is a denial, never an allow.
3. Authoritative Risk: Caller claims can never lower risk. RTQ computes it.
4. Single-Use Tickets: HMAC-SHA256, bound to exact operation. Replay rejected.
5. Fail-Closed Sandbox: No sandbox → no execution.
6. Redacted Audit: Secrets scrubbed before logging.

### Twelve Invariants (INV-01 through INV-12)

- INV-01: Unregistered capability → rejection (packages/core/src/registry.ts)
- INV-02: Replay of consumed ticket → 409 Conflict (packages/core/src/ticket-store.ts)
- INV-03: Caller risk-lowering attempt → ignored (packages/risk/src/engine.ts)
- INV-04: Missing policy rule → denial (packages/policy/src/engine.ts)
- INV-05: Expired ticket → rejection (packages/core/src/ticket-store.ts)
- INV-06: Tampered ticket signature → rejection (packages/crypto/src/hmac.ts)
- INV-07: Missing sandbox → execution blocked (packages/sandbox/src/factory.ts)
- INV-08: Audit event contains no raw secrets (packages/audit/src/emitter.ts)
- INV-09: Clarification loop terminates or times out (packages/clarification/src/engine.ts)
- INV-10: Policy engine rejects unknown capability (packages/policy/src/engine.ts)
- INV-11: Ticket is single-use (packages/core/src/ticket-store.ts)
- INV-12: Platform sandbox restricts filesystem (packages/sandbox/src/seatbelt.ts)

## Platform Support

- macOS: Seatbelt (sandbox-exec) — 104 tests passing
- Linux: bubblewrap (bwrap) — 57 tests passing
- Windows: AppContainer + Job Object — 61 tests passing

## Quick Start

\`\`\`typescript
import { createRTQ } from "@rtq/security";

const rtq = createRTQ({ signingKey: process.env.RTQ_SIGNING_KEY! });

rtq.registerCapability({
  name: "files.read",
  version: 1,
  description: "Read a file inside the workspace",
  inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
  risk: { base: "low" },
  execute: async (ctx, input) => ({ ok: true, data: { input } }),
});
\`\`\`

## Links

- Documentation: ${APP_INFO.siteUrl}/docs
- GitHub: ${APP_INFO.repo}
- License: Apache-2.0
- Keywords: latestinssan, Ponsri School, PONSRISCHOOL, Aartiq
`;

  return new NextResponse(content, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
