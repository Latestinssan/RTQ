# Changelog

All notable changes to RTQ are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) for releases.
Until the first tagged release, changes accumulate under `[Unreleased]`.

## [Unreleased]

### Added

- **Security model** (`@rtq/core`): separated
  Command / Capability / Risk / Policy / Clarification / Approval / Ticket /
  Execution / Sandbox / Audit types; capability registry with explicit
  registration and versioning; JSON-schema input validation.
- **Authoritative risk engine** (`@rtq/risk`): origin escalation
  (remote/mobile/unknown escalate; `unknown` is never treated as local),
  sensitive-resource prefixes, caller claims can only raise the baseline.
- **Default-deny policy** (`@rtq/policy`): declarative allow/deny rules with
  glob matching (`files.**` → `^files\..*$`), deny-beats-allow, policy-mandated
  clarification and approval, optional risk overrides.
- **Clarification** (`@rtq/clarification`): structured questions when
  security-critical parameters are missing; no authorization in that state.
- **Approval** (`@rtq/approval`): strategies (automatic, user_confirmation,
  device_verification, biometric, qr, custom); QR challenge-response protocol;
  single-use short-lived `ChallengeRegistry` with expired-challenge cleanup;
  signed `DeviceApproval` (HMAC-SHA256), constant-time verification.
- **Authorization tickets** (`@rtq/core`): HMAC-SHA256 over a canonical body
  binding capability+version+input-hash+actor+resource+risk+policy-version+
  approval-method+origin+challenge+expiry+nonce; synchronous atomic
  single-use redemption; replay/tamper/expiry/version-change rejection;
  invalidation on capability replacement.
- **OS sandboxing** (`@rtq/sandbox`): macOS Seatbelt, Linux bubblewrap, Windows
  AppContainer+Job Object (PowerShell runner in
  `packages/sandbox/scripts/windows-runner.ps1`). Fail-closed construction;
  per-layer enforcement reporting; explicit `useSandbox: false` escape hatch
  that reports `sandboxed: false` (never silent).
- **Filesystem policy layer** (`@rtq/sandbox`): canonicalization (`~`,
  realpath, symlink resolution), separator-aware boundary matching,
  read/write/delete separation, default-deny on empty allowlists.
- **Audit** (`@rtq/audit`): structured event taxonomy over all security
  transitions, redacting sinks, bounded memory sink, JSONL file sink.
- **Pipeline façade** (`@rtq/security`): `createRTQ` with
  register/replace capability, policy, clarification, approval providers,
  authorize, approval payload/QR, submitApproval (with challenge-binding
  anti-substitution checks), execute, diagnostics, MCP ticket bindings.
- **CLI** (`@rtq/cli`): `capabilities`, `policy check` (with `--origin`),
  `sandbox test`, `verify signature`, `diagnostics`.
- **Tests**: 146 tests across unit / contract / integration / real OS
  enforcement suites, including real macOS Seatbelt enforcement tests, replay
  and tamper rejection, approval substitution, origin spoofing, claimed-risk
  non-downgrade, and secret redaction.
- **Docs**: design and security overview, threat model, security verification
  matrix, CLI reference, platform support, provenance/source audit trail,
  testing strategy.
- **CI**: GitHub Actions matrix workflows (macOS / Ubuntu / Windows) for
  type-check + format + build + tests, security suites, sandbox enforcement
  suites (real backend where available, explicit skips otherwise), and
  docs-site build.

### Changed

- Nothing released yet (pre-1.0 work is collapsed into this initial entry).

### Fixed

- Nothing released yet.
