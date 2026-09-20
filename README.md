# RTQ — Risk-Adaptive Capability Security Runtime

[![npm version](https://img.shields.io/npm/v/@rtq/security.svg?style=flat-square)](https://www.npmjs.com/package/@rtq/security)
[![npm downloads](https://img.shields.io/npm/dm/@rtq/security.svg?style=flat-square&label=npm%20downloads)](https://www.npmjs.com/package/@rtq/security)
[![GitHub Release](https://img.shields.io/github/v/release/Latestinssan/RTQ?style=flat-square)](https://github.com/Latestinssan/RTQ/releases/tag/v1.0.0)
[![GitHub All Releases Downloads](https://img.shields.io/github/downloads/Latestinssan/RTQ/total?style=flat-square&color=emerald&label=github%20downloads)](https://github.com/Latestinssan/RTQ/releases/tag/v1.0.0)
[![APK Downloads](https://img.shields.io/github/downloads/Latestinssan/RTQ/v1.0.0/app-release.apk?style=flat-square&label=apk%20downloads&color=blue)](https://github.com/Latestinssan/RTQ/releases/download/v1.0.0/app-release.apk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](LICENSE)

RTQ is a security-focused capability-security runtime for Node.js, TypeScript, Model Context Protocol (MCP) servers, and mobile approval hosts. Security-critical packages declare **zero third-party npm runtime dependencies**. It turns _"can this agent/tool do this?"_ into an **evidence-backed security pipeline**:

```
Command → Capability (registered) → Risk (authoritative) → Policy (default-deny)
       → Clarification (missing critical params) → Approval (human/device)
       → Authorization Ticket (signed, single-use, bound) → Execution (OS-sandboxed)
       → Audit (structured, redacted)
```

---

## 📥 Downloads & Live Metrics

| Resource                      | Link / Badge                                                                                                                                                                                                                         | Description                                                  |
| :---------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------- |
| **GitHub Release v1.0.0**     | [![GitHub All Releases Downloads](https://img.shields.io/github/downloads/Latestinssan/RTQ/total?style=flat-square&color=emerald&label=Release%20Downloads)](https://github.com/Latestinssan/RTQ/releases/tag/v1.0.0)                | Source code, tag provenance, and release metadata            |
| **Android Mobile App (.apk)** | [![APK Downloads](https://img.shields.io/github/downloads/Latestinssan/RTQ/v1.0.0/app-release.apk?style=flat-square&label=APK%20Downloads&color=blue)](https://github.com/Latestinssan/RTQ/releases/download/v1.0.0/app-release.apk) | Flutter Android app for local Ed25519 QR challenge approvals |
| **npm Registry**              | [![npm downloads](https://img.shields.io/npm/dm/@rtq/security.svg?style=flat-square&label=npm%20Downloads)](https://www.npmjs.com/package/@rtq/security)                                                                             | All 12 published `@rtq/*` packages                           |

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

RTQ was created to solve this problem for developers everywhere — packaging a security-focused capability security runtime into a clean suite of reusable packages. Developed and validated through automated security testing, RTQ allows developers to integrate capability security, OS-enforced sandboxing, Model Context Protocol (MCP) policy enforcement, and mobile QR challenge-response approvals into their applications without having to build security infrastructure from scratch.

---

## 🔬 System Capabilities & Limits

To provide full transparency, RTQ clearly delineates what is implemented, what is verified in CI, and what is outside its current scope:

### ✅ Implemented

- **Capability Registry**: Explicit capability registration with schema validation.
- **Authoritative Risk Engine**: Structural risk evaluation where caller-supplied risk claims can only raise, never lower, calculated risk.
- **Declarative Default-Deny Policy**: Missing or unlisted rules evaluate to denial.
- **HMAC-Signed Single-Use Tickets**: Ticket redemption state is managed by a process-local, atomic ticket store.
- **OS Sandbox Adapters**: Wrappers for macOS Seatbelt (`sandbox-exec`), Linux bubblewrap (`bwrap`), and Windows AppContainer + Job Objects.
- **Redacted Audit Logging**: Automatic sanitization of secrets in security logs.
- **QR / Mobile Approval Protocol**: Single-use challenge-response protocol with zero PIN transmission.

### 🧪 Verified in CI

- **12 Automated Security Invariants**: Rigorous test suites asserting invariants INV-01 through INV-12.
- **Cross-Platform Enforcement**: Automated sandbox execution tests on macOS, Linux, and Windows runners.
- **Cross-Language Protocol Vectors**: Node.js vs Dart byte-exact challenge signature validation.
- **430+ Unit & Integration Tests**: Comprehensive test coverage across all 12 monorepo packages.

### ⚠️ Scope & Evidence Limits

- **Process-Local Ticket Store**: Ticket single-use redemption is currently enforced in process-local memory. Distributed multi-node replay protection requires a distributed shared ticket store backend.
- **No Formal Security Proof**: Automated CI testing establishes empirical verification, not formal mathematical proof.
- **Platform Key Storage**: Mobile keypairs use platform secure storage (`flutter_secure_storage` utilizing Android Keystore / iOS Keychain where supported by OS and hardware capabilities).
- **Host Trusted Computing Base (TCB)**: RTQ governs authorization, ticket verification, and process containment. The internal logic of registered execution handlers (e.g. `system.execute`) remains part of the host application's trusted computing base.
- **No Independent Third-Party Audit**: RTQ is an open-source alpha security runtime that has not undergone an independent third-party security audit.

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
// Note: RTQ enforces authorization & sandboxing, but handler safety remains part of host TCB
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
4. **Local Ed25519 Signing**: The mobile app verifies the challenge locally and signs the approval using device platform secure storage (`flutter_secure_storage` utilizing Android Keystore / iOS Keychain where supported).

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

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). RTQ is an original implementation created by [Latestinssan](https://github.com/Latestinssan).
