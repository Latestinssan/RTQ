# RTQ — Risk-Adaptive Capability Security Runtime

[![npm version](https://img.shields.io/npm/v/@rtq/security.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/security)
[![GitHub Release](https://img.shields.io/github/v/release/Latestinssan/RTQ?style=flat-square)](https://github.com/Latestinssan/RTQ/releases/tag/v1.0.0)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](LICENSE)

RTQ is a production-grade, dependency-free capability-security runtime for Node.js, TypeScript, Model Context Protocol (MCP) servers, and mobile approval hosts. It turns _"can this agent/tool do this?"_ into a **provable security pipeline**:

```
Command → Capability (registered) → Risk (authoritative) → Policy (default-deny)
       → Clarification (missing critical params) → Approval (human/device)
       → Authorization Ticket (signed, single-use, bound) → Execution (OS-sandboxed)
       → Audit (structured, redacted)
```

---

## 📥 Downloads & Packages

| Resource                      | Link                                                                                                        | Description                                                  |
| :---------------------------- | :---------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------- |
| **GitHub Release v1.0.0**     | [Release Notes & Assets](https://github.com/Latestinssan/RTQ/releases/tag/v1.0.0)                           | Source code, tag provenance, and release metadata            |
| **Android Mobile App (.apk)** | [Direct APK Download (62 MB)](https://github.com/Latestinssan/RTQ/releases/download/v1.0.0/app-release.apk) | Flutter Android app for local Ed25519 QR challenge approvals |
| **npm Registry**              | [@rtq Scope on npm](https://www.npmjs.com/org/rtq)                                                          | All 12 published `@rtq/*` packages                           |

### Published npm Packages

| Package              | npm Link                                                                                                                          | Responsibility                                                                         |
| :------------------- | :-------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------- |
| `@rtq/security`      | [![npm](https://img.shields.io/npm/v/@rtq/security.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/security)           | Full pipeline façade (`createRTQ`)                                                     |
| `@rtq/cli`           | [![npm](https://img.shields.io/npm/v/@rtq/cli.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/cli)                     | Security CLI (`capabilities`, `policy check`, `sandbox test`, `verify`, `diagnostics`) |
| `@rtq/mcp`           | [![npm](https://img.shields.io/npm/v/@rtq/mcp.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/mcp)                     | Business-Grade MCP integration layer & security gateway                                |
| `@rtq/core`          | [![npm](https://img.shields.io/npm/v/@rtq/core.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/core)                   | Capability registry, ticket store, and schema validation                               |
| `@rtq/crypto`        | [![npm](https://img.shields.io/npm/v/@rtq/crypto.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/crypto)               | Canonical JSON, HMAC-SHA256, nonces, constant-time compare, redaction                  |
| `@rtq/sandbox`       | [![npm](https://img.shields.io/npm/v/@rtq/sandbox.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/sandbox)             | OS enforcement: macOS Seatbelt, Linux bubblewrap, Windows AppContainer                 |
| `@rtq/approval`      | [![npm](https://img.shields.io/npm/v/@rtq/approval.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/approval)           | Approval strategies, QR/mobile challenge-response protocol                             |
| `@rtq/mobile`        | [![npm](https://img.shields.io/npm/v/@rtq/mobile.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/mobile)               | Mobile approval host transport and pairing server                                      |
| `@rtq/risk`          | [![npm](https://img.shields.io/npm/v/@rtq/risk.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/risk)                   | Authoritative risk engine (caller claims can never downgrade)                          |
| `@rtq/policy`        | [![npm](https://img.shields.io/npm/v/@rtq/policy.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/policy)               | Declarative default-deny rules, glob matching, risk overrides                          |
| `@rtq/clarification` | [![npm](https://img.shields.io/npm/v/@rtq/clarification.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/clarification) | Ambiguity resolution & structured security parameter questions                         |
| `@rtq/audit`         | [![npm](https://img.shields.io/npm/v/@rtq/audit.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/audit)                 | Structured, redacted security event logger                                             |

---

## 💡 Why RTQ Was Created

While developing **Aartiq**, a disproportionate amount of engineering time was spent repeatedly implementing OS-level sandboxing, capability scoping, fine-grained permission gating, and challenge-response authorization from scratch.

RTQ was created to solve this problem once and for all — packaging a battle-tested, risk-adaptive capability security runtime into a clean suite of reusable packages. With RTQ, developers can instantly integrate capability security, OS-enforced sandboxing, Model Context Protocol (MCP) policy enforcement, and mobile QR challenge-response approvals into their applications without having to build security infrastructure from scratch.

---

## 🚀 Quick Start & Usage Guide

### 1. Installation

Install the main façade package in your project:

```sh
npm install @rtq/security
```

Or install the RTQ CLI globally:

```sh
npm install -g @rtq/cli
```

### 2. Runtime Capability & Policy Enforcement

```ts
import { createRTQ } from "@rtq/security";

// Initialize runtime with signing key from environment
const rtq = createRTQ({
  signingKey: process.env.RTQ_SIGNING_KEY!,
});

// Step 1: Explicitly register capabilities (no ambient execution)
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
  execute: async (ctx, input) => ({ ok: true, data: { path: input.path } }),
});

// Step 2: Register policy (default-deny: unlisted capabilities are denied)
rtq.registerPolicy({
  kind: "allow",
  capability: "files.read",
  reason: "Allow workspace file reads",
});

// Step 3: Authorize operation (receives cryptographically signed ticket)
const auth = await rtq.authorize({
  capability: "files.read",
  version: 1,
  input: { path: "/workspace/report.md" },
});

if (auth.decision === "allowed") {
  // Step 4: Execute inside OS sandbox with single-use ticket
  const outcome = await rtq.execute(auth.ticketId);
  console.log("Result:", outcome.result);
} else if (auth.decision === "approval_required") {
  console.log(
    "Human/Mobile approval required. Challenge ID:",
    auth.challengeId,
  );
}
```

### 3. Using the Security CLI

The `@rtq/cli` package provides actionable security inspection and testing commands:

```sh
# Inspect registered capabilities
RTQ_SIGNING_KEY=secret npx rtq capabilities --config settings/config.js

# Test policy enforcement against a candidate command
RTQ_SIGNING_KEY=secret npx rtq policy check command.json --config settings/config.js --origin remote

# Run real OS-level sandbox enforcement checks
npx rtq sandbox test

# Verify an authorization ticket signature
RTQ_SIGNING_KEY=secret npx rtq verify signature --ticket ticket.json

# Run environment and platform security diagnostics
npx rtq diagnostics
```

### 4. Model Context Protocol (MCP) Gateway Integration

Protect MCP servers with RTQ's security gateway:

```ts
import { createMCPGateway } from "@rtq/mcp";

const gateway = createMCPGateway({
  signingKey: process.env.RTQ_SIGNING_KEY!,
  enforceSandboxing: true,
});

// Register MCP tool mapping to capability
gateway.registerToolCapability({
  toolName: "execute_script",
  capabilityName: "system.execute",
  version: 1,
});
```

### 5. Mobile Approval App (Android Flutter App)

For high-risk operations requiring user verification:

1. **Download the Android APK**: [Download v1.0.0 APK](https://github.com/Latestinssan/RTQ/releases/download/v1.0.0/app-release.apk).
2. Install on Android device (Android 12+, Java 17/Dart 3.11 target).
3. **Scan QR Challenge**: When RTQ returns `approval_required`, it renders a single-use QR challenge.
4. **Local Ed25519 Signing**: The mobile app verifies the challenge locally and signs the approval using a hardware-backed Ed25519 key without transmitting PINs or static secrets.

---

## 🛡️ Security Posture & Guarantees

- **Explicit Surface**: Unregistered capabilities are denied by default.
- **Default-Deny Policy**: Absence of an explicit allow rule results in denial.
- **Authoritative Risk Engine**: Caller-supplied risk claims can only escalate risk, never lower it.
- **Single-Use Signed Tickets**: HMAC-SHA256 authorization tickets bound to capability, input hash, actor, origin, and nonce.
- **Fail-Closed OS Sandboxing**: macOS Seatbelt (`sandbox-exec`), Linux bubblewrap (`bwrap`), and Windows AppContainer + Job Object. If sandbox creation fails, execution is refused.
- **Redacted Audit Logging**: Structured security logs automatically sanitize passwords, keys, and tokens.

---

## 🧪 Testing & Verification

```sh
npm run typecheck     # Whole-repo TypeScript validation
npm run format:check  # Code formatting validation
npm run build         # Build all 12 packages
npm test              # Run 430+ unit, contract & security tests
```

---

## 📄 License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). RTQ is an original, dependency-free implementation created by [Latestinssan](https://github.com/Latestinssan).
