# Security

RTQ is a security library; its own security posture is treated as a product
requirement with the same rigor as its API.

## Reporting a vulnerability

**Do not open a public issue for a confirmed or suspected vulnerability.**

Report privately to the maintainers. Until a dedicated security contact
exists for this repository, report via a private email or a private advisory
draft (GitHub → Security → Report a vulnerability). Include:

- the affected package and version (or commit),
- a minimal reproduction,
- the impact you believe applies,
- any suggested fix.

You will receive an acknowledgement within 5 business days. We ask that you do
not disclose details publicly until a fix is released (coordinated
disclosure).

## Security model (summary)

Every layer denies by default and fails closed:

1. **Explicit capability surface.** Only `registerCapability` results can be
   authorized. `packages/core/src/capability-registry.ts` denies unregistered
   names and mismatched versions.
2. **Default-deny policy.** A missing policy rule is a denial.
   `packages/policy/src/index.ts`.
3. **Authoritative risk.** `packages/risk/src/index.ts` computes risk from
   capability factors, origin and resource. A caller-claimed low risk can
   never downgrade the result (verified in
   `tests/security/pipeline.test.ts`).
4. **Single-use signed tickets.** `packages/core/src/ticket-store.ts` signs a
   canonical body HMAC-SHA256 and redeems atomically; replay, tamper, expiry,
   invalidation and version changes are rejected with explicit codes.
5. **Challenge-response approvals.** `packages/approval/src/challenge.ts` —
   QR scanning awards nothing; a device that performed local authentication
   signs the exact challenge; challenges are single-use and short-lived.
6. **Fail-closed OS sandbox.** `packages/sandbox/src/index.ts` — if the
   platform backend cannot be constructed or verified, execution is refused.
   No unsandboxed fallback exists; `useSandbox: false` is explicit and
   reported.
7. **Redacted audit.** `packages/audit/src/index.ts` redacts secret-shaped
   values before any sink sees them.

## Verification

- Automated invariant tests: `tests/security/pipeline.test.ts` (replay,
  tamper, substitution, origin spoofing, risk non-downgrade, redaction).
- Real OS enforcement: `tests/sandbox/darwin.test.ts` runs `sandbox-exec`
  profiles on macOS; Linux bwrap and Windows runner tests run where the
  backend is installed (explicit skips otherwise — never faked passes).
- Per-claim verification status: see
  [docs/SECURITY_VERIFICATION_MATRIX.md](docs/SECURITY_VERIFICATION_MATRIX.md).
- Full threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Verification provenance

Links below are intentionally **not fabricated**. After the first CI run and
first tag, this section is completed with:

- source-tree SHA(s) of the verified revision,
- GitHub Actions workflow run IDs for `ci`, `security`, `sandbox`, and
  `docs` workflows,
- the exact commit in which they were recorded.

The analysis documents themselves cite exact file:line locations in the
repository (`docs/source.md`, `docs/THREAT_MODEL.md`), which are verifiable
locally at any revision.

## Secrets handling

- `RTQ_SIGNING_KEY` (or an equivalent secret-store value) must never be
  committed. The CLI and security façade read it from the environment.
- Device keys live in platform secure storage in production (Keychain /
  Credential Locker / TPM); RTQ itself never persists them.
- Sandboxed processes never inherit ambient credentials: the environment is
  constructed from an explicit allowlist (`packages/sandbox/src/env.ts`).
