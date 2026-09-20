# Contributing

RTQ is a security library: correctness and honesty of claims matter more than
velocity. Please read the [security model](SECURITY.md) before contributing.

## Ground rules

1. **Never weaken a denial.** Default deny, fail closed, and "missing
   policy ≠ allow" are invariants. A change that adds a silent allow path or
   an unsandboxed fallback will be rejected.
2. **Never claim what is not verified.** If a test cannot prove an OS-level
   guarantee, the docs must say so. JS tests never assert sandbox enforcement;
   real OS enforcement tests skip with a reason when the backend is absent.
3. **No ambient authority.** Caller-supplied risk, origin hints and metadata
   are treated as untrusted; they can raise, never lower, authority.
4. **Match the file layout.** Each concern lives in its own `@rtq/*` package.
   Keep dependencies acyclic: `crypto` ← `core/audit` ← `policy/risk/
clarification/approval` ← `sandbox` ← `security` ← `cli`.

## Setup

```sh
npm install
npm run typecheck
npm run test
```

Node >= 20 and npm >= 10 are expected. TypeScript is strict (`strict: true`,
`noUncheckedIndexedAccess`).

## What to change and how

- **New security logic** ships with tests in the matching `tests/` folder and
  a row in `docs/SECURITY_VERIFICATION_MATRIX.md`.
- **Test labels** must be accurate: label each suite `unit`, `contract`,
  `integration`, or `real OS enforcement` (see `docs/testing.md`). The
  Darwin suite is `real OS enforcement` and is gated on `/usr/bin/sandbox-exec`.
- **Docs** that touch security claims must cite exact `file:line` locations —
  analysis documents never assert behavior that the code does not implement.
- **CLI changes** keep every command actionable: output must tell the caller
  what to do, and exit codes must distinguish "OK" from "not OK".

## Formatting

```sh
npm run format       # prettier --write
npm run format:check # CI gate
```

## Tests

```sh
npm run test:unit     # unit suites
npm run test:security # security pipeline + filesystem policy
npm run test:sandbox  # OS enforcement + backend unit tests
npm run test:coverage # coverage report
```

A change that breaks a suite in any supported platform (macOS / Linux /
Windows) without an explicit, justified skip is not ready to merge.

## Commits and releases

- Keep commits focused; include the test that motivates the change.
- Before a release: run the full `ci` script, update `CHANGELOG.md`, tag a
  version, and record the CI run IDs + tree SHA in `SECURITY.md`
  (Verification provenance). Never fabricate run IDs or SHAs.

## Code of conduct

Be respectful and assume good faith. Security review is thorough precisely
because the stakes are high — disagreement on an invariant is resolved by
evidence (a test), not by assertion.
